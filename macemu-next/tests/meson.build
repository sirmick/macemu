# CPU tests
test_unicorn_m68k = executable('test_unicorn_m68k',
  'cpu/test_unicorn_m68k.c',
  dependencies: [cpu_dep, unicorn_dep, threads_dep, m_dep],
  include_directories: include_directories('../src/cpu')
)

test('Unicorn M68K wrapper test', test_unicorn_m68k)

# Boot test
subdir('boot')
