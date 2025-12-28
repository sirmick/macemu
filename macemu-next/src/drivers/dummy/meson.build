# Dummy drivers for minimal boot testing
dummy_sources = [
  'audio_dummy.cpp',
  'clip_dummy.cpp',
  'ether_dummy.cpp',
  'prefs_dummy.cpp',
  'prefs_editor_dummy.cpp',
  'scsi_dummy.cpp',
  'serial_dummy.cpp',
  'user_strings_dummy.cpp',
  'video_dummy.cpp',
  'xpram_dummy.cpp',
]

dummy_inc = include_directories(
  '.',
  '../../common/include',
  '../../core',
)

dummy_lib = static_library('dummy_drivers',
  dummy_sources,
  include_directories: dummy_inc,
)

dummy_dep = declare_dependency(
  link_with: dummy_lib,
  include_directories: dummy_inc,
)
