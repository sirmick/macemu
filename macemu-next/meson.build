project('macemu-next', ['c', 'cpp'],
  version: '2.0.0',
  default_options: [
    'c_std=c11',
    'cpp_std=c++17',
    'warning_level=2',
    'buildtype=debugoptimized'
  ]
)

# Options
cpu_backend = get_option('cpu_backend')  # 'unicorn', 'uae', 'dualcpu'
build_basilisk = get_option('basilisk')
build_sheepshaver = get_option('sheepshaver')

# Dependencies
cc = meson.get_compiler('c')
cpp = meson.get_compiler('cpp')

# Unicorn dependency (static library we just built)
unicorn_inc = include_directories('external/unicorn/include')
unicorn_lib = cc.find_library('unicorn',
  dirs: [meson.current_source_dir() / 'external/unicorn/build'],
  static: true,
  required: (cpu_backend in ['unicorn', 'dualcpu'])
)
unicorn_dep = declare_dependency(
  include_directories: unicorn_inc,
  dependencies: [unicorn_lib]
)

# Other dependencies
threads_dep = dependency('threads', required: true)
m_dep = cc.find_library('m', required: true)  # Math library for Unicorn

# Compiler flags based on backend
if cpu_backend == 'dualcpu'
  add_project_arguments('-DCPU_EMULATION_DUALCPU', language: ['c', 'cpp'])
endif

# Build info
message('Build configuration:')
message('  CPU backend: ' + cpu_backend)
message('  Build BasiliskII: ' + build_basilisk.to_string())
message('  Build SheepShaver: ' + build_sheepshaver.to_string())

# Subdirectories
subdir('src/cpu')
subdir('src/core')
subdir('src/drivers')

# Main executable
macemu_next = executable('macemu-next',
  'src/main.cpp',
  link_with: [core_lib, driver_lib, cpu_lib],
  dependencies: [unicorn_dep, threads_dep, m_dep],
  include_directories: [
    include_directories('src/common/include'),
    include_directories('src/core'),
    include_directories('src/cpu'),
    include_directories('src/cpu/uae_cpu'),
    include_directories('src/drivers'),
  ]
)

# Tests
if get_option('tests')
  subdir('tests')
endif
