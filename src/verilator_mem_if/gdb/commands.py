# Copyright IDEX Biometrics
# Licensed under the MIT License, see LICENSE
# SPDX-License-Identifier: MIT

# Copyright IDEX Biometrics
# Licensed under the MIT License, see LICENSE
# SPDX-License-Identifier: MIT

import gdb
import argparse
import sys
import traceback
from contextlib import contextmanager

class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs['formatter_class'] = lambda prog: argparse.RawTextHelpFormatter(prog, max_help_position=80, width=200)
        super().__init__(*args, **kwargs)
        
    def exit(self, status=None, message=None):
        if message is not None:
            sys.exit(message.strip())
        else:
            sys.exit(status)

    def parse_args(self, *args, **kwargs):
        args = super().parse_args(*args, **kwargs)
        return args


class register:
    """Decorator class used to register each class with GDB. """

    global_prefix = []

    @staticmethod
    @contextmanager
    def prefix(prefix):
        register.global_prefix.append(prefix)
        yield
        register.global_prefix.pop()

    def __init__(self, cmdname=None, cmdtype=None, repeat=False, prefix=False, parent=[]):
        self.cmdname = cmdname
        self.cmdtype = cmdtype
        self.crepeat = repeat
        self.cprefix = prefix

        if not isinstance(parent, list):
            parent = [parent]
        self.parents = parent

    def __call__(self, cmd):
        if self.cmdname is None:
            self.cmdname = cmd.__name__.lower()
        if self.cmdtype is None:
            self.cmdtype = cmd.gdb_class
        name = " ".join(self.global_prefix + self.parents + [self.cmdname])
        cmd(name, self.cmdtype, self.crepeat, self.cprefix)
        return cmd


class Command(gdb.Command):
    gdb_class = gdb.COMMAND_USER

    def __init__(self, cmdname, cmdtype, repeat, prefix):
        self.cmdname = cmdname
        self.cmdtype = cmdtype
        self.repeat  = repeat
        self.prefix  = prefix

        # Setup a parser for the command
        self.parser = ArgumentParser(prog=self.cmdname, description=self.__doc__)
        self.setup(self.parser)

        # gdb generates its help from the docstring.
        # We temporarilly overwrite it with argparse's output.
        old_doc, self.__doc__ = self.__doc__, self.parser.format_help().strip()

        # Call gdb's init. This will cause the command to be registerd.
        super().__init__(cmdname, cmdtype, prefix=prefix)

        # Restore the docstring so that it is usefull when looking
        # up help in python or when used for any other puprpose.
        self.__doc__ = old_doc

    def setup(self, parser):
        pass

    def invoke(self, args, from_tty):

        if not self.repeat:
            self.dont_repeat()

        self.parser.set_defaults(from_tty=from_tty)

        # Not sure we trust gdb to split the line as we want it, but
        # until there are problems we'll let him give it a shot.
        args = gdb.string_to_argv(args)

        try:
            args = self.parser.parse_args(args)
            self.run(args)
        except KeyboardInterrupt as e:
            pass
        except SystemExit as e:
            if isinstance(e.code, int):
                raise gdb.GdbError("command exited with status %s." % e.code)
            elif e.code:
                raise gdb.GdbError(str(e))
        except gdb.GdbError:
            # This type of error can be used to report failure to gdb.
            # We let is pass through so that applications can print errors.
            # Still, the prefered way for an extension to do this
            # would be to simply use exit().
            raise
        except BaseException as e:
            # This is a bug or unexpected circumstance.
            if getattr(args, "from_tty", True):
                print(traceback.format_exc(), end="")
                print(e)
            else:
                raise

class UserCommand(Command):
    gdb_class = gdb.COMMAND_USER

# ...