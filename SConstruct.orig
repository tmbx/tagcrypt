import commands, os, sys

# Per Laurent Birtz example.
EnsurePythonVersion(2,3)
SourceSignatures('MD5')
TargetSignatures('content')

tagcrypt_FILES = ['tagcrypt.c',
                  'tagcryptgen.c',
                  'tagcryptpkey.c',
                  'tagcryptsignature.c',
                  'tagcryptsignsubpacket.c',
                  'tagcryptskey.c',
                  'tagcryptsymkey.c',
                  'tagcryptotut.c']

tagcrypt_HEADERS = ['tagcrypt.h',
                    'tagcryptgen.h',
                    'tagcryptlog.h',
                    'tagcryptpkey.h',
                    'tagcryptsignature.h',
                    'tagcryptskey.h',
                    'tagcryptsymkey.h',
                    'tagcryptversion.h',
                    'tagcryptotut.h',
                    'tagcryptgen.h']

opts = Options('build.conf')
opts.AddOptions(
    BoolOption('mudflap', 'Build with mudflap (gcc 4.x)', 0),
    BoolOption('mpatrol', 'Build with mpatrol', 0),
    BoolOption('debug', 'Compile with all debug options turned on', 1),
    ('libktools_include', 'Location of include files for libktools', '../libktools/src'),
    ('libktools_libpath', 'Location of library files for libktools', '../libktools/build'),
    ('LIBDIR', 'Directory to install library files', '/usr/lib'),
    ('INCDIR', 'Directory where to install the header files', '/usr/include/tagcrypt')
    )

#
# Environment setup.
#

# Setup the build environment.
env = Environment(options = opts)
opts.Save('build.conf', env)

# Generate the help text.
Help(opts.GenerateHelpText(env))

env['CPPDEFINES'] = ['__UNIX__']
env['CCFLAGS'] = ['-W', '-Wall']
env['LDFLAGS'] = ['-rdynamic']
env['CPPPATH'] = [str(env['libktools_include'])] + ["."]
env['LIBPATH'] = [str(env['libktools_libpath'])]
env['LIBS']    = []

# Set the switches for mudflap is required
if env['mudflap']: env['CCFLAGS'] += ['-fmudflap']

# Check for debug build.
if env['debug']:
    env['CCFLAGS'] += ['-g', '-O0']
    env['LDFLAGS'] += ['-g']
else:
    env['CCFLAGS'] += ['-O2', '-fno-strict-aliasing']
        
#
# Build configuration.
#

# Custom test to get all libraries needed to link with libgcrypt
def CheckGCrypt(context):
    context.Message("Checking for libgcrypt-config...")
    if commands.getstatusoutput('which libgcrypt-config')[0] == 0:
        env['LIBS'] += commands.getoutput('libgcrypt-config --libs').strip().split()    
        context.Result('ok')
        return 1
    else:
        context.Result('failed')
        return 0

if not env.GetOption('clean'):
    conf = env.Configure(custom_tests = {'CheckGCrypt' : CheckGCrypt})
    if not conf.CheckGCrypt():
        print "libgcrypt not found."
        Exit(1)
    if not conf.CheckLib('fl', autoadd=1):
        print "GNU flex library not found."
        Exit(1)
    if not conf.CheckLib('ktools', autoadd=1):
        print "libktools not found."
        Exit(1)
    if env['mudflap']:
        if conf.CheckLib('mudflap', autoadd=1):
            print "mudflap not found."
            Exit(1)
    if env['mpatrol']:
        if conf.CheckLib('mpatrol', autoadd=1):
            print "MPatrol not found."
            Exit(1)
        if conf.CheckLib('bfd', autoadd=1):
            print "libbfd not found.  It is required with MPatrol."
            Exit(1)
    conf.Finish()

#
# Target setup.
#

tagcrypt_shared_OBJS = []
for s in tagcrypt_FILES:
    n = os.path.splitext(s)[0]
    tagcrypt_shared_OBJS.append(env.SharedObject(target = 'build/' + n, source = s))

tagcrypt_static_OBJS = []
for s in tagcrypt_FILES:
    n = os.path.splitext(s)[0]
    tagcrypt_static_OBJS.append(env.StaticObject(target = 'build/' + n, source = s))

# Build the libs.
lib_static = env.StaticLibrary(target = 'build/libtagcrypt1.a',
                               source = tagcrypt_static_OBJS)
lib_shared = env.SharedLibrary(target = 'build/libtagcrypt1.so.0.0',
                               LIBS = env['LIBS'],
                               source = tagcrypt_shared_OBJS,
                               SHLIBSUFFIX = '',
                               LINKFLAGS = '-Wl,-soname,libtagcrypt1.so.0')

if 'test' in COMMAND_LINE_TARGETS:
    env.Program(target = 'test',
                source = ['test.c', lib_static],
                LINKFLAGS = '-g -Lbuild -ltagcrypt1 -lktools0')

# Must make the SONAME link.
if 'install' in COMMAND_LINE_TARGETS:
    # Install data.
    libdir = str(env['LIBDIR']);
    env.Install(libdir, lib_shared)
    env.Install(libdir, lib_static)
    env.Alias('install', libdir)

    # Install the header files.
    incdir = str(env['INCDIR'])
    env.Install(incdir, source = tagcrypt_HEADERS)
    env.Alias('install', incdir)
    
    env.Command(libdir + '/libtagcrypt1.so.0', 'build/libtagcrypt1.so.0.0',
                'cd ' + libdir + ' && ln -s libtagcrypt1.so.0.0 libtagcrypt1.so.0')
    env.Command(libdir + '/libtagcrypt1.so', 'build/libtagcrypt1.so.0.0',
                'cd ' + libdir + ' && ln -s libtagcrypt1.so.0.0 libtagcrypt1.so')
