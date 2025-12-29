# Boot test executable

boot_test_sources = [
  'test_boot.cpp',
]

boot_test_inc = include_directories(
  '.',
  '../../src/common/include',
  '../../src/core',
  '../../src/cpu',
  '../../src/cpu/uae_cpu',
  '../../src/drivers',
)

boot_test = executable('test_boot',
  boot_test_sources,
  include_directories: boot_test_inc,
  link_with: [core_lib, driver_lib, cpu_lib],
  dependencies: [unicorn_dep, threads_dep, m_dep],
)
