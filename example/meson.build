examples = [ 'passthrough', 'passthrough_fh',
             'hello', 'hello_ll', 'hello_ll_uds',
             'printcap', 'ioctl_client', 'poll_client',
             'ioctl', 'cuse', 'cuse_client' ]

if not platform.endswith('bsd') and platform != 'dragonfly'
    examples += 'passthrough_ll'

    # According to Conrad Meyer <cem@freebsd.org>, FreeBSD doesn't
    # support mounting files, This is enforced in vfs_domount_first()
    # with the v_type != VDIR check.
    examples += [ 'null' ]
endif

threaded_examples = [ 'notify_inval_inode',
                      'invalidate_path',
                      'notify_store_retrieve',
                      'notify_inval_entry',
                      'poll' ]

foreach ex : examples
    executable(ex, ex + '.c',
               dependencies: [ libfuse_dep ],
               install: false)
endforeach


foreach ex : threaded_examples
    executable(ex, ex + '.c',
               dependencies: [ thread_dep, libfuse_dep ],
               install: false)
endforeach

if not platform.endswith('bsd') and platform != 'dragonfly' and add_languages('cpp', required : false)
    executable('passthrough_hp', 'passthrough_hp.cc',
               dependencies: [ thread_dep, libfuse_dep ],
               install: false)
endif

# TODO: Link passthrough_fh with ulockmgr if available

#cjson_library = cc.find_library('cjson', required : true)
jsonc_library = cc.find_library('json-c', required : true)
curl_library = cc.find_library('curl', required : true)
ssl_library = cc.find_library('crypto', required : true)
uuid_library = cc.find_library('uuid', required : true)
#executable('tcloudfs', ['tcloud/tcloudfs.c', 'tcloud/tcloud_drive.c', 'tcloud/tcloud_buffer.c', 'tcloud/j2sobject_cloud.c', 'tcloud/j2s/j2sobject.c'],
#    dependencies: [ thread_dep, libfuse_dep, cjson_library ],
#    include_directories: 'tcloud/j2s',
#        install: false)

executable('cloud_j2sobject', ['tcloud/tests/cloud_j2sobject.c', 'tcloud/j2sobject_cloud.c', 'tcloud/j2s/j2sobject.c'],
    dependencies: [ thread_dep, jsonc_library],
    include_directories: ['tcloud/j2s', 'tcloud'],
        install: false)

executable('tcloudfs_ll', ['tcloud/tcloudfs_ll.c', 'tcloud/tcloud_drive.c', 'tcloud/tcloud_buffer.c', 'tcloud/j2sobject_cloud.c', 'tcloud/j2s/j2sobject.c', 'tcloud/xxtea.c'],
    dependencies: [ thread_dep, libfuse_dep, jsonc_library, curl_library, uuid_library, ssl_library ],
    include_directories: 'tcloud/j2s',
        install: false)
