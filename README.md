Objective-C helper
==================

# Presentation

This IDA plugin helps you reverse-engineer Objective-C code. The main feature
is a decompiler hook cleaning up the pseudocode output, mainly removing
superfluous Objective-C runtime calls related to ARC (Automatic Reference
Couting) automatically added by the compiler.

# Decompiler output cleanup

"Modern" Objective-C compilers implement ARC (Automatic Reference Counting).
This feature allows developers to write Objective-C code without explicitely
calling lifetime-related methods such as `retain` and `release`.

Instead, the compiler automatically generates calls to the dedicated
Objective-C runtime functions: they mainly concern object lifetime such as
`objc_retain()`, `objc_release()`, `objc_claimAutoreleasedReturnValue()`, and
strong/weak objects manipulation (usually linked to properties) such as
`objc_storeStrong()`, `objc_loadWeakRetained()`.

From the point of view of a reverse engineer simply analyzing an Objective-C
implementation, those generated calls have two drawbacks:
- They usually just add noise to the final pseudocode and make it harder for the
  analyst to focus on the relevant code ;
- Their return values are sometimes seen by IDA as opaque as they prevent type
  propagation.

Everytime the plugin is loaded, a Hex-Rays microcode hook is installed and
calls to ARC runtime functions are removed (replaced by a microinstruction
replicating the CPU/memory state after the call). This may remove around 10%
to 20% of total lines of code.

## Usage

The hook is automatically installed when the plugin is loaded. It can be
toggled through the option located in `Edit -> Objective-C helper -> Toggle
microcode optimizer`.

## Example

Below is an excerpt of a pseudocode without the hook installed. Calls made to
`objc_claimAutoreleasedReturnValue()` are seen as opaque by IDA (they are not
handled by native Objective-C support).

```c
UIViewControllerViewAnimator *from;
id view;
id window;
id controller;

// [...]
view = objc_claimAutoreleasedReturnValue(
  -[UIViewControllerViewAnimator view](
    from, "view"));
window = objc_claimAutoreleasedReturnValue(
  objc_msgSend(v77, "window"));
controller = objc_claimAutoreleasedReturnValue(
  +[UIWindowController windowControllerForWindow:](
    &OBJC_CLASS___UIWindowController,
    "windowControllerForWindow:",
    window));
objc_release(v78);
objc_release(v77);
```

Below is the result after hooking.

```c
UIViewController *from;
UIWindowController *controller;

// [...]
controller = +[UIWindowController windowControllerForWindow:](
  &OBJC_CLASS___UIWindowController,
  "windowControllerForWindow:",
  -[UIView window](-[UIViewController view](from, "view"), "window"));
```

# Propagation of calls made to a selector

It is possible to list all calls made to the selector linked to the method
implementation that is being currently analyzed.

## Usage

When your cursor is located in the implementation of an Objective-C method,
**Ctrl-Shift-Q** automatically propagates all method calls using the related
selector to this implementation. You can then use the native *Jump to xref* (X)
menu to navigate.

Note that as selectors are shared between methods, all propagated
cross-references do not necessarily end up in the implementation you are
currently reverse-engineering. Consider them as **candidate calls**, as further
analysis is needed to determine the actually invoked implementation.
