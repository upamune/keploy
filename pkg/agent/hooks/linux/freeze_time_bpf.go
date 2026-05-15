//go:build linux

// Package linux implements Linux-specific agent hooks.
package linux

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

const (
	freezeKindTimespec = 1
	freezeKindTimeval  = 2
	freezeKindTime     = 3

	sysEnterArg0Offset = 16
	sysEnterArg1Offset = 24
	sysExitRetOffset   = 16

	amd64PtRegsAXOffset = 80
	amd64PtRegsSIOffset = 104
	amd64PtRegsDIOffset = 112

	arm64PtRegsX0Offset = 0
	arm64PtRegsX1Offset = 8
)

type freezeConfig struct {
	Enabled uint64
	Sec     uint64
	Nsec    uint64
}

type freezeCallState struct {
	UserPtr uint64
	Kind    uint64
}

func (h *Hooks) attachFreezeTimePrograms() error {
	cfgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "keploy_freeze_time_cfg",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  24,
		MaxEntries: 1,
	})
	if err != nil {
		return fmt.Errorf("create freeze-time config map: %w", err)
	}
	stateMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "keploy_freeze_time_state",
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  16,
		MaxEntries: 65536,
	})
	if err != nil {
		cfgMap.Close()
		return fmt.Errorf("create freeze-time state map: %w", err)
	}

	specs := []struct {
		name     string
		category string
		event    string
		insns    asm.Instructions
		optional bool
	}{
		{"keploy_enter_clock_gettime", "syscalls", "sys_enter_clock_gettime", freezeEnterClockGettime(stateMap.FD(), h.objects.TargetNamespacePids.FD(), h.objects.ExcludedPids.FD()), false},
		{"keploy_exit_clock_gettime", "syscalls", "sys_exit_clock_gettime", freezeExitProgram(stateMap.FD(), cfgMap.FD(), freezeKindTimespec, sysExitRetOffset), false},
		{"keploy_enter_gettimeofday", "syscalls", "sys_enter_gettimeofday", freezeEnterPointerArg(stateMap.FD(), h.objects.TargetNamespacePids.FD(), h.objects.ExcludedPids.FD(), freezeKindTimeval), false},
		{"keploy_exit_gettimeofday", "syscalls", "sys_exit_gettimeofday", freezeExitProgram(stateMap.FD(), cfgMap.FD(), freezeKindTimeval, sysExitRetOffset), false},
		{"keploy_enter_time", "syscalls", "sys_enter_time", freezeEnterPointerArg(stateMap.FD(), h.objects.TargetNamespacePids.FD(), h.objects.ExcludedPids.FD(), freezeKindTime), true},
		{"keploy_exit_time", "syscalls", "sys_exit_time", freezeExitProgram(stateMap.FD(), cfgMap.FD(), freezeKindTime, sysExitRetOffset), true},
	}

	links := make([]link.Link, 0, len(specs))
	programs := make([]*ebpf.Program, 0, len(specs))
	for _, s := range specs {
		prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name:         s.name,
			Type:         ebpf.TracePoint,
			License:      "GPL",
			Instructions: s.insns,
		})
		if err != nil {
			closeFreezeResources(links, programs, cfgMap, stateMap)
			return fmt.Errorf("load freeze-time program %s: %w", s.name, err)
		}
		tp, err := link.Tracepoint(s.category, s.event, prog, nil)
		if err != nil {
			if s.optional && errors.Is(err, os.ErrNotExist) {
				h.logger.Debug("optional freeze-time tracepoint is unavailable", zap.String("event", s.event), zap.Error(err))
				prog.Close()
				continue
			}
			closeFreezeResources(links, programs, cfgMap, stateMap)
			return fmt.Errorf("attach freeze-time tracepoint %s: %w", s.event, err)
		}
		programs = append(programs, prog)
		links = append(links, tp)
	}

	h.freezeMaps = append(h.freezeMaps, cfgMap, stateMap)
	h.freezeLinks = append(h.freezeLinks, links...)
	h.freezePrograms = append(h.freezePrograms, programs...)
	h.freezeConfigMap = cfgMap
	if err := h.attachFreezeLibcUprobes(stateMap, cfgMap); err != nil {
		h.logger.Warn("freeze-time libc uprobes were not attached; syscall hooks remain active but vDSO-backed runtime clocks may not freeze", zap.Error(err))
	}
	h.logger.Info("freeze-time eBPF hooks attached")
	return nil
}

func (h *Hooks) attachFreezeLibcUprobes(stateMap, cfgMap *ebpf.Map) error {
	arg0Offset, arg1Offset, retOffset, err := libcRegisterOffsets()
	if err != nil {
		return err
	}
	libcPath, err := findLibc()
	if err != nil {
		return err
	}
	ex, err := link.OpenExecutable(libcPath)
	if err != nil {
		return fmt.Errorf("open libc for freeze-time uprobes: %w", err)
	}

	entries := []struct {
		name   string
		symbol string
		kind   int32
		insns  asm.Instructions
	}{
		{"keploy_uprobe_clock_gettime", "clock_gettime", freezeKindTimespec, freezeEnterClockGettimeFromRegs(stateMap.FD(), h.objects.TargetNamespacePids.FD(), h.objects.ExcludedPids.FD(), arg0Offset, arg1Offset)},
		{"keploy_uprobe_gettimeofday", "gettimeofday", freezeKindTimeval, freezeEnterPointerArgFromRegs(stateMap.FD(), h.objects.TargetNamespacePids.FD(), h.objects.ExcludedPids.FD(), arg0Offset, freezeKindTimeval)},
		{"keploy_uprobe_time", "time", freezeKindTime, freezeEnterPointerArgFromRegs(stateMap.FD(), h.objects.TargetNamespacePids.FD(), h.objects.ExcludedPids.FD(), arg0Offset, freezeKindTime)},
	}
	var attached int
	var errs []error
	for _, e := range entries {
		enterProg, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name:         e.name,
			Type:         ebpf.Kprobe,
			License:      "GPL",
			Instructions: e.insns,
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("load %s: %w", e.name, err))
			continue
		}
		enterLink, err := ex.Uprobe(e.symbol, enterProg, nil)
		if err != nil {
			enterProg.Close()
			errs = append(errs, fmt.Errorf("attach uprobe %s: %w", e.symbol, err))
			continue
		}

		exitProg, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name:         e.name + "_ret",
			Type:         ebpf.Kprobe,
			License:      "GPL",
			Instructions: freezeExitProgram(stateMap.FD(), cfgMap.FD(), e.kind, retOffset),
		})
		if err != nil {
			enterLink.Close()
			enterProg.Close()
			errs = append(errs, fmt.Errorf("load %s_ret: %w", e.name, err))
			continue
		}
		exitLink, err := ex.Uretprobe(e.symbol, exitProg, nil)
		if err != nil {
			exitProg.Close()
			enterLink.Close()
			enterProg.Close()
			errs = append(errs, fmt.Errorf("attach uretprobe %s: %w", e.symbol, err))
			continue
		}
		h.freezeLinks = append(h.freezeLinks, enterLink, exitLink)
		h.freezePrograms = append(h.freezePrograms, enterProg, exitProg)
		attached++
	}
	if attached == 0 {
		return errors.Join(errs...)
	}
	if len(errs) > 0 {
		h.logger.Warn("some freeze-time libc uprobes were not attached", zap.Errors("errors", errs))
	}
	h.logger.Info("freeze-time libc uprobes attached", zap.String("libc", libcPath), zap.Int("symbols", attached))
	return nil
}

func findLibc() (string, error) {
	candidates := []string{
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/lib/aarch64-linux-gnu/libc.so.6",
		"/usr/lib/aarch64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
		"/lib/libc.musl-x86_64.so.1",
		"/usr/lib/libc.musl-x86_64.so.1",
		"/lib/libc.musl-aarch64.so.1",
		"/usr/lib/libc.musl-aarch64.so.1",
	}
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && info.Mode()&0o111 != 0 {
			return path, nil
		}
	}
	return "", errors.New("libc executable not found in known locations")
}

func libcRegisterOffsets() (arg0 int16, arg1 int16, ret int16, err error) {
	switch runtime.GOARCH {
	case "amd64":
		return amd64PtRegsDIOffset, amd64PtRegsSIOffset, amd64PtRegsAXOffset, nil
	case "arm64":
		return arm64PtRegsX0Offset, arm64PtRegsX1Offset, arm64PtRegsX0Offset, nil
	default:
		return 0, 0, 0, fmt.Errorf("libc freeze-time uprobes are not implemented for %s", runtime.GOARCH)
	}
}

func closeFreezeResources(links []link.Link, programs []*ebpf.Program, maps ...*ebpf.Map) {
	for _, l := range links {
		if l != nil {
			_ = l.Close()
		}
	}
	for _, p := range programs {
		if p != nil {
			_ = p.Close()
		}
	}
	for _, m := range maps {
		if m != nil {
			_ = m.Close()
		}
	}
}

func freezeEnterClockGettime(stateMapFD, targetPidsMapFD, excludedPidsMapFD int) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, excludedPidsMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -12),
		asm.FnMapLookupElem.Call(),
		asm.JNE.Imm(asm.R0, 0, "exit"),
		asm.LoadMapPtr(asm.R1, targetPidsMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -12),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.LoadMem(asm.R2, asm.R6, sysEnterArg0Offset, asm.DWord),
		asm.JEq.Imm(asm.R2, 0, "save"),
		asm.JEq.Imm(asm.R2, 5, "save"),
		asm.Ja.Label("exit"),

		asm.LoadMem(asm.R3, asm.R6, sysEnterArg1Offset, asm.DWord).WithSymbol("save"),
		asm.JEq.Imm(asm.R3, 0, "exit"),
		asm.StoreMem(asm.RFP, -24, asm.R3, asm.DWord),
		asm.Mov.Imm(asm.R4, freezeKindTimespec),
		asm.StoreMem(asm.RFP, -16, asm.R4, asm.DWord),
		asm.LoadMapPtr(asm.R1, stateMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -24),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	}
}

func freezeEnterPointerArg(stateMapFD, targetPidsMapFD, excludedPidsMapFD int, kind int32) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, excludedPidsMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -12),
		asm.FnMapLookupElem.Call(),
		asm.JNE.Imm(asm.R0, 0, "exit"),
		asm.LoadMapPtr(asm.R1, targetPidsMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -12),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.LoadMem(asm.R3, asm.R6, sysEnterArg0Offset, asm.DWord),
		asm.JEq.Imm(asm.R3, 0, "exit"),
		asm.StoreMem(asm.RFP, -24, asm.R3, asm.DWord),
		asm.Mov.Imm(asm.R4, kind),
		asm.StoreMem(asm.RFP, -16, asm.R4, asm.DWord),
		asm.LoadMapPtr(asm.R1, stateMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -24),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	}
}

func freezeUprobeEnterClockGettime(stateMapFD, targetPidsMapFD, excludedPidsMapFD int) asm.Instructions {
	return freezeEnterClockGettimeFromRegs(
		stateMapFD,
		targetPidsMapFD,
		excludedPidsMapFD,
		amd64PtRegsDIOffset,
		amd64PtRegsSIOffset,
	)
}

func freezeUprobeEnterPointerArg(stateMapFD, targetPidsMapFD, excludedPidsMapFD int, kind int32) asm.Instructions {
	return freezeEnterPointerArgFromRegs(
		stateMapFD,
		targetPidsMapFD,
		excludedPidsMapFD,
		amd64PtRegsDIOffset,
		kind,
	)
}

func freezeEnterClockGettimeFromRegs(stateMapFD, targetPidsMapFD, excludedPidsMapFD int, clockIDOffset, pointerOffset int16) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, excludedPidsMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -12),
		asm.FnMapLookupElem.Call(),
		asm.JNE.Imm(asm.R0, 0, "exit"),
		asm.LoadMapPtr(asm.R1, targetPidsMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -12),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.LoadMem(asm.R2, asm.R6, clockIDOffset, asm.DWord),
		asm.JEq.Imm(asm.R2, 0, "save"),
		asm.JEq.Imm(asm.R2, 5, "save"),
		asm.Ja.Label("exit"),

		asm.LoadMem(asm.R3, asm.R6, pointerOffset, asm.DWord).WithSymbol("save"),
		asm.JEq.Imm(asm.R3, 0, "exit"),
		asm.StoreMem(asm.RFP, -24, asm.R3, asm.DWord),
		asm.Mov.Imm(asm.R4, freezeKindTimespec),
		asm.StoreMem(asm.RFP, -16, asm.R4, asm.DWord),
		asm.LoadMapPtr(asm.R1, stateMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -24),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	}
}

func freezeEnterPointerArgFromRegs(stateMapFD, targetPidsMapFD, excludedPidsMapFD int, pointerOffset int16, kind int32) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, excludedPidsMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -12),
		asm.FnMapLookupElem.Call(),
		asm.JNE.Imm(asm.R0, 0, "exit"),
		asm.LoadMapPtr(asm.R1, targetPidsMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -12),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.LoadMem(asm.R3, asm.R6, pointerOffset, asm.DWord),
		asm.JEq.Imm(asm.R3, 0, "exit"),
		asm.StoreMem(asm.RFP, -24, asm.R3, asm.DWord),
		asm.Mov.Imm(asm.R4, kind),
		asm.StoreMem(asm.RFP, -16, asm.R4, asm.DWord),
		asm.LoadMapPtr(asm.R1, stateMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -24),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	}
}

func freezeExitProgram(stateMapFD, cfgMapFD int, kind int32, retOffset int16) asm.Instructions {
	ins := asm.Instructions{
		asm.Mov.Reg(asm.R8, asm.R1),
		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.LoadMem(asm.R2, asm.R8, retOffset, asm.DWord),
	}
	if kind != freezeKindTime {
		ins = append(ins, asm.JNE.Imm(asm.R2, 0, "delete"))
	}
	ins = append(ins,
		asm.LoadMapPtr(asm.R1, stateMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Reg(asm.R6, asm.R0),
		asm.LoadMem(asm.R2, asm.R6, 8, asm.DWord),
		asm.JNE.Imm(asm.R2, kind, "delete"),
		asm.Mov.Imm(asm.R2, 0),
		asm.StoreMem(asm.RFP, -12, asm.R2, asm.Word),
		asm.LoadMapPtr(asm.R1, cfgMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -12),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "delete"),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.LoadMem(asm.R2, asm.R7, 0, asm.DWord),
		asm.JNE.Imm(asm.R2, 1, "delete"),
		asm.LoadMem(asm.R1, asm.R6, 0, asm.DWord),
		asm.JEq.Imm(asm.R1, 0, "delete"),
	)

	switch kind {
	case freezeKindTimespec:
		ins = append(ins,
			asm.LoadMem(asm.R2, asm.R7, 8, asm.DWord),
			asm.StoreMem(asm.RFP, -32, asm.R2, asm.DWord),
			asm.LoadMem(asm.R2, asm.R7, 16, asm.DWord),
			asm.StoreMem(asm.RFP, -24, asm.R2, asm.DWord),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -32),
			asm.Mov.Imm(asm.R3, 16),
			asm.FnProbeWriteUser.Call(),
		)
	case freezeKindTimeval:
		ins = append(ins,
			asm.LoadMem(asm.R2, asm.R7, 8, asm.DWord),
			asm.StoreMem(asm.RFP, -32, asm.R2, asm.DWord),
			asm.LoadMem(asm.R2, asm.R7, 16, asm.DWord),
			asm.Div.Imm(asm.R2, 1000),
			asm.StoreMem(asm.RFP, -24, asm.R2, asm.DWord),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -32),
			asm.Mov.Imm(asm.R3, 16),
			asm.FnProbeWriteUser.Call(),
		)
	case freezeKindTime:
		ins = append(ins,
			asm.LoadMem(asm.R2, asm.R7, 8, asm.DWord),
			asm.StoreMem(asm.RFP, -32, asm.R2, asm.DWord),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -32),
			asm.Mov.Imm(asm.R3, 8),
			asm.FnProbeWriteUser.Call(),
		)
	}

	ins = append(ins,
		asm.LoadMapPtr(asm.R1, stateMapFD).WithSymbol("delete"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapDeleteElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	return ins
}

func freezeConfigFor(ts time.Time, enabled bool) freezeConfig {
	ts = ts.UTC()
	var e uint64
	if enabled && !ts.IsZero() {
		e = 1
	}
	return freezeConfig{
		Enabled: e,
		Sec:     uint64(ts.Unix()),
		Nsec:    uint64(ts.Nanosecond()),
	}
}

func (h *Hooks) updateFreezeConfig(ts time.Time, enabled bool) error {
	if h.freezeConfigMap == nil {
		if enabled {
			h.logger.Debug("freeze-time eBPF config map is not attached yet")
		}
		return nil
	}
	key := uint32(0)
	cfg := freezeConfigFor(ts, enabled)
	if err := h.freezeConfigMap.Update(key, cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update freeze-time config map: %w", err)
	}
	return nil
}
