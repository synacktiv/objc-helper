"""
Microcode optimizer plugin to remove all Objective-C helpers related to objects
lifetime-handling. This allows proper type propagation in the decompiler
output and cleans up the pseudocode.
"""
import re
import idaapi as ida
import idautils
import idc


__version__ = '1.0.0'


def log(*args):
    print(f'{ObjcHelperPlugin.wanted_name}:', *args)


class ObjcOptimizer(ida.optinsn_t):
    # Microcode register identifiers
    REGS = {'x0': 8, 'x1': 16, 'cs': 848}
    # List of functions to be optimized off
    NOP_FUNCS = ['objc_release', 'objc_autoreleasePoolPush',
                 'objc_autoreleasePoolPop', 'objc_destroyWeak']
    MOV_FUNCS = ['objc_retain', 'objc_retainAutorelease', 'objc_autorelease',
                 'objc_retainBlock', 'objc_autoreleaseReturnValue',
                 'objc_retainAutoreleaseReturnValue',
                 'objc_unsafeClaimAutoreleasedReturnValue',
                 'objc_claimAutoreleasedReturnValue',
                 'objc_retainAutoreleasedReturnValue']
    STX_FUNCS = ['objc_storeStrong', 'objc_storeWeak', 'objc_copyWeak',
                 'objc_initWeak']
    LDX_FUNCS = ['objc_loadWeakRetained']

    @staticmethod
    def __ins_in_funcs(ins, funcs):
        if ins.l.t == ida.mop_h:
            return any(ins.is_helper(func) for func in funcs)
        elif (ins.l.t == ida.mop_v and
              (name := ida.get_name(ins.l.g)) is not None):
            return any(re.match(rf'^(j_)?_{func}(_\d+)?$', name) is not None
                       for func in map(re.escape, funcs))

    def __make_stx(self, ins):
        ins.opcode = ida.m_stx
        ins.l.make_reg(self.REGS['x1'], 8) # What to store
        ins.d.make_reg(self.REGS['x0'], 8) # Where to store
        ins.r.make_reg(self.REGS['cs'], 2) # sel?
        return True

    def __make_ldx(self, ins):
        ins.opcode = ida.m_ldx
        ins.l.make_reg(self.REGS['cs'], 2) # sel?
        ins.r.make_reg(self.REGS['x0'], 8) # What to store
        ins.d.make_reg(self.REGS['x0'], 8) # Where to store
        return True

    def __make_mov(self, ins):
        # Retain-flavored calls are converted to `mov` instructions. Example:
        #   id objc_retain@<x0>(id@<x20>)
        # will be converted to
        #   mov x20.8, x0.8

        if (fi := ins.d.f) is not None:
            # Inspect function call information
            if fi.args.empty(): # Ensure an argument is being passed
                return False
            dest = fi.retregs[0] # Destination register
            arg = fi.args[0] # Register containing object address
            if arg.t != ida.mop_r:
                # We only handle registers here. There can be memory accesses
                # sometimes, ignore them
                return False
            assert arg.size == dest.size
        else:
            # Default to id(id)
            arg = ida.mop_t()
            arg.make_reg(self.REGS['x0'], 8) # x0
            dest = ida.mop_t()
            dest.make_reg(self.REGS['x0'], 8) # x0

        # Actually build the instruction
        ins.opcode = ida.m_mov
        ins.l.make_reg(arg.r, arg.size)
        ins.d.make_reg(dest.r, dest.size)
        ins.r = ida.mop_t()
        return True

    def __clean(self, blk, ins):
        if ins.opcode != ida.m_call:
            return False

        if self.__ins_in_funcs(ins, self.NOP_FUNCS):
            # Release-flavored calls are simply converted to no-ops
            blk.make_nop(ins)
            return True
        elif self.__ins_in_funcs(ins, self.MOV_FUNCS):
            return self.__make_mov(ins)
        elif self.__ins_in_funcs(ins, self.STX_FUNCS):
            return self.__make_stx(ins)
        elif self.__ins_in_funcs(ins, self.LDX_FUNCS):
            return self.__make_ldx(ins)

    def func(self, blk, ins, optflags):
        # Run on preoptimized maturity to avoid bothering with memory accesses
        # in call instructions
        if blk.mba.maturity >= ida.MMAT_PREOPTIMIZED:
            if self.__clean(blk, ins):
                # Check that our modifications are correct
                blk.mba.verify(True)
                return 1
        return 0


class ObjcOptimizeAction(ida.action_handler_t):
    def __init__(self):
        self.__installed = False
        self.__optimizer = None

    def install(self):
        if self.__optimizer is None:
            assert ida.init_hexrays_plugin()
            self.__optimizer = ObjcOptimizer()
        self.__optimizer.install()
        self.__installed = True
        log('Optimizer installed')
        return True

    def remove(self):
        if self.__optimizer is None:
            return False
        self.__optimizer.remove()
        self.__installed = False
        log('Optimizer removed')
        return True

    def activate(self, ctx):
        if self.__installed:
            self.remove()
        else:
            self.install()
        return 1

    # This action is always available.
    def update(self, ctx):
        return ida.AST_ENABLE_ALWAYS


def iter_xrefs_from_seg(ea, name):
    suffix = f':{name}'
    for xref in idautils.XrefsTo(ea):
        xref_ea = xref.frm
        if (seg := ida.getseg(xref_ea)) is None:
            continue
        segname = ida.get_segm_name(seg) or ''
        if segname == name or segname.endswith(suffix):
            yield xref_ea


def iter_objc_xrefs(ea):
    # First, get xref to the corresponding class method list
    meth_xref = iter_xrefs_from_seg(ea, '__objc_methlist')
    if (meth_ea := next(meth_xref, None)) is None:
        raise ValueError('not an Objective-C method')
    assert next(meth_xref, None) is None

    # Then, grab the location of selector references. They do not belong to a
    # specific segment although many of them are stored in libobjc.A:__OBJC_RO
    xrefs = [xref.to for xref in idautils.XrefsFrom(meth_ea - 8)]
    # In the shared cache, selector offsets are relative to a dummy selector,
    # so the highest xref is the actual selector reference.
    is_shc = len(xrefs) == 2
    sel_ea = max(xrefs)

    # Fetch all registered references to the selector
    if is_shc:
        # Shared cache implement trampolines
        for selref in iter_xrefs_from_seg(sel_ea, '__objc_selrefs'):
            # Finally, grab all trampolines referencing this selector
            for xref in idautils.XrefsTo(selref):
                name = ida.get_name(xref.frm) or ''
                if name.startswith('_objc_msgSend$'):
                    # Yield all references to this trampoline
                    yield from idautils.XrefsTo(xref.frm)
    else:
        # Otherwise selector references are direct
        for xref in idautils.XrefsTo(sel_ea):
            segname = ida.get_segm_name(ida.getseg(xref.frm))
            if not segname.startswith('__objc_'):
                yield xref


def propagate_objc_xrefs(func):
    """
    This function runs in an Objective-C method implementation. It goes back up
    to objc_msgSend() calls using the corresponding selector and propagates
    xrefs to the actual implementation.
    """
    # In recent iOS shared caches, all `objc_msgSend()` calls are replaced by
    # trampoline functions, which simply set up the selector before actually
    # calling `objc_msgSend()`.
    count = 0
    for xref in iter_objc_xrefs(func.start_ea):
        # Propagate trampoline cross-references to the potential implementation
        if xref.type in (ida.dr_U, ida.dr_O, ida.dr_W, ida.dr_R,
                         ida.dr_T, ida.dr_I, ida.dr_S):
            # I have never seen a data xref to a trampoline, but who knows?
            add_ref = ida.add_dref
        else:
            add_ref = ida.add_cref
        add_ref(xref.frm, func.start_ea, xref.type)
        count += 1
    return count


class ObjcPropagateAction(ida.action_handler_t):
    def activate(self, ctx):
        if (func := ida.get_func(ida.get_screen_ea())) is not None:
            func_name = ida.get_name(func.start_ea) or '???'
            try:
                count = propagate_objc_xrefs(func)
            except ValueError as exc:
                log(f'Function {func_name}: {exc}')
            else:
                log(f'{count} cross-references propagated to {func_name}')
        else:
            log('Must be placed in an Objective-C method implementation')
        return 1

    # This action is always available.
    def update(self, ctx):
        return ida.AST_ENABLE_ALWAYS


class ObjcRetypeAllStubs(ida.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.retype_all_segments()

    def update(self, ctx):
        return ida.AST_ENABLE_ALWAYS


class IDPHooks(ida.IDP_Hooks):
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__()

    def ev_auto_queue_empty(self, _type):
        if _type == ida.AU_FINAL:
            self.plugin.auto_final_done()
        return 0


class IDBHooks(ida.IDB_Hooks):
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__()

    def segm_added(self, s):
        name = ida.get_segm_name(s)
        if name.endswith(":__objc_stubs"):
            self.plugin.add_segment(s.start_ea)


class ObjcHelperPlugin(ida.plugin_t):
    ACTION_RETYPE_ALL_STUBS = "objc:retype_objc_stubs"
    OBJC_MSG_SEND_PROTO = "_QWORD objc_msgSend(void*, const char*, ...);"
    MENU_PATH = 'Edit/Objective-C helper/'
    flags = ida.PLUGIN_HIDE
    wanted_name = 'Objective-C helper'
    wanted_hotkey = ''
    comment = ('Remove calls to Objective-C helpers generated by the compiler')
    help = ''

    def __init__(self):
        super().__init__()
        self.__initialized = False
        self.__optimize_action = None
        self.__idph = None
        self.__idbh = None
        self.__waiting_segments = []

    def term(self):
        self.__term_actions()
        self.__term_hooks()

    def __term_actions(self):
        if self.__optimize_action is not None:
            self.__optimize_action.remove()
            ida.unregister_action(self.ACTION_RETYPE_ALL_STUBS)

    def __term_hooks(self):
        if self.__idph is not None:
            self.__idph.unhook()
        if self.__idbh is not None:
            self.__idbh.unhook()

    def init(self):
        if not self.__initialized:
            print(f'{self.wanted_name} version {__version__}')

            self.__init_actions()
            self.__init_hooks()

            self.__initialized = True
        return ida.PLUGIN_KEEP

    def __init_actions(self):
        self.__optimize_action = ObjcOptimizeAction()
        self.__optimize_action.install()
        action_desc = ida.action_desc_t('objchelper:optimize',
                                        'Toggle microcode optimizer',
                                        self.__optimize_action)
        ida.register_action(action_desc)
        ida.attach_action_to_menu(self.MENU_PATH, 'objchelper:optimize',
                                  ida.SETMENU_APP)

        action_desc = ida.action_desc_t('objchelper:propagate',
                                        'Propagate xrefs to current method',
                                        ObjcPropagateAction(),
                                        'Ctrl-Shift-Q')
        ida.register_action(action_desc)
        ida.attach_action_to_menu(self.MENU_PATH, 'objchelper:propagate',
                                  ida.SETMENU_APP)


        action_desc = ida.action_desc_t(self.ACTION_RETYPE_ALL_STUBS,
                                                'Retype all Objective-C stubs',
                                                ObjcRetypeAllStubs(self))

        ida.register_action(action_desc)
        ida.attach_action_to_menu(self.MENU_PATH, self.ACTION_RETYPE_ALL_STUBS, ida.SETMENU_APP)

    def __init_hooks(self):
        self.__idbh = IDBHooks(self)
        self.__idbh.hook()

        self.__idph = IDPHooks(self)
        self.__idph.hook()

    def run(self, arg):
        pass

    def add_segment(self, ea):
        self.__waiting_segments.append(ea)

    def auto_final_done(self):
        while len(self.__waiting_segments):
            ea = self.__waiting_segments.pop()
            self.retype_stubs(ea)

    def retype_all_segments(self):
        for s in idautils.Segments():
            if idc.get_segm_name(s).endswith(":__objc_stubs"):
                self.retype_stubs(s)

        log("Retyped all segments")

    def retype_stubs(self, ea):
        s = ida.getseg(ea)

        for f in idautils.Functions(s.start_ea, s.end_ea):
            name = ida.get_name(f)
            if name.startswith("_objc_msgSend"):
                idc.SetType(f, self.OBJC_MSG_SEND_PROTO)


def PLUGIN_ENTRY():
    return ObjcHelperPlugin()
