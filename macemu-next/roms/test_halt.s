; test_halt.s - Simplest test ROM
;
; Tests: Can CPU execute one instruction and halt?
; Expected: 1 instruction executed, CPU halted
;
; This is the absolute simplest test - just STOP (HALT) the CPU.

	.org	$0

	; Entry point
	dc.l	$00002000	; Initial SP (stack at 8KB)
	dc.l	start		; Initial PC

start:
	stop	#$2700		; Halt CPU with all interrupts masked
