helper_modern = get_option('helper_modern')
helper_legacy = get_option('helper_legacy')
helper_compat = ''
helper_depends = []

agent_modern = get_option('agent_modern')
agent_legacy = get_option('agent_legacy')
agent_compat = ''
agent_emulated_modern = get_option('agent_emulated_modern')
agent_emulated_legacy = get_option('agent_emulated_legacy')
agent_depends = []

gadget_compat = ''
gadget_depends = []

server_compat = ''
server_depends = []

no_overridden_compat_bits = \
    helper_modern == 'auto' and helper_legacy == 'auto' \
    and agent_modern == 'auto' and agent_legacy == 'auto' \
    and agent_emulated_modern == 'auto' and agent_emulated_legacy == 'auto'

if no_overridden_compat_bits
  build_py = [python, files('build.py')]

  components = []
  if build_gadget
    components += 'gadget'
  endif
  if build_server
    components += 'server'
  endif

  setup_result = run_command(build_py,
    'setup',
    meson.is_subproject() ? 'subproject' : 'project',
    meson.current_build_dir(),
    host_os,
    host_abi,
    ','.join(get_option('compat')),
    get_option('assets'),
    ','.join(components),
    check: true
  )
  setup_output = setup_result.stdout().strip()
  if setup_output != ''
    tokens = setup_output.split(' ')
    varnames = tokens[0].split(',')
    outputs = tokens[1].split(',')
    depfile = tokens[2]

    if host_os_family == 'darwin'
      install = false
      install_dir = asset_dir
    else
      install = true
      install_dir = []
      foreach varname : varnames
        if get_option('assets') == 'installed' or varname.startswith('gadget_')
          install_dir += varname.endswith('_modern') ? asset_dir_modern : asset_dir_legacy
        else
          install_dir += false
        endif
      endforeach
    endif

    arch_support = custom_target('arch-support',
      output: outputs,
      command: [
        build_py,
        'compile',
        meson.current_build_dir(),
        meson.global_build_root(),
      ],
      depfile: depfile,
      install: install,
      install_dir: install_dir,
    )

    i = 0
    foreach output : arch_support.to_list()
      outpath = output.full_path()
      varname = varnames[i]

      set_variable(varname, outpath)

      if varname.startswith('helper_')
        helper_compat = outpath
        helper_depends += arch_support
      elif varname.startswith('agent_')
        agent_compat = outpath
        agent_depends += arch_support
      elif varname.startswith('gadget_')
        gadget_compat = outpath
        gadget_depends += arch_support
      elif varname.startswith('server_')
        server_compat = outpath
        server_depends += arch_support
      else
        assert(false, f'unexpected variable name: @varname@')
      endif

      i += 1
    endforeach
  endif
endif
