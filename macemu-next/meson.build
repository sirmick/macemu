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

# Build info
message('Build configuration:')
message('  CPU backend: ' + cpu_backend)
message('  Build BasiliskII: ' + build_basilisk.to_string())
message('  Build SheepShaver: ' + build_sheepshaver.to_string())

# Subdirectories
subdir('src/cpu')
subdir('src/core')
subdir('src/drivers/dummy')

# Tests
if get_option('tests')
  subdir('tests')
endif
