# UAE CPU Core Build
#
# Minimal build of UAE M68K emulation for dual-CPU validation

uae_sources = [
  'newcpu.cpp',
  'cpuemu_nf.cpp',   # No-flags version (JIT disabled)
  'cpustbl_nf.cpp',  # No-flags version
  'readcpu.cpp',
  'memory.cpp',
  'basilisk_glue.cpp',
  'basilisk_stubs.cpp',  # Temporary stubs for missing BasiliskII functions
  'cpuemu_ff_aliases.cpp',  # Auto-generated _ff to _nf function aliases
]

uae_inc = include_directories('.')
common_inc = include_directories('../../common/include')

uae_lib = static_library('uae_cpu',
  uae_sources,
  include_directories: [uae_inc, common_inc, include_directories('../..')],
  cpp_args: [
    '-DCPU_EMU_SIZE=0',
    '-DREAL_ADDRESSING=0',
    '-DDIRECT_ADDRESSING=1',
    '-DUSE_JIT=0',
    '-DUSE_PREFETCH_BUFFER=0',
    '-DNOFLAGS',
    '-Wno-unused-variable',
    '-Wno-unused-parameter',
    '-Wno-unused-function',
    '-Wno-sign-compare',
    '-Wno-unused-but-set-variable',
    '-Wno-parentheses',
    '-Wno-format',
    '-Wno-narrowing',
  ]
)

uae_dep = declare_dependency(
  link_with: uae_lib,
  include_directories: uae_inc
)
