cpu_sources = []
cpu_deps = []

if cpu_backend == 'unicorn' or cpu_backend == 'dualcpu'
  cpu_sources += [
    'unicorn_wrapper.c',
  ]
  cpu_deps += unicorn_dep
endif

if cpu_backend == 'dualcpu'
  cpu_sources += [
    'dualcpu.c',
    'uae_stubs.c',  # Placeholder until UAE is integrated
  ]
endif

# Build CPU library
cpu_lib = static_library('cpu',
  cpu_sources,
  dependencies: cpu_deps,
  include_directories: include_directories('.')
)

cpu_dep = declare_dependency(
  link_with: cpu_lib,
  include_directories: include_directories('.')
)
