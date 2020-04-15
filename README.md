# KernelGDIDraw
The program draws by calling win32k gdi functions while NtGdiDdDDISubmitCommand is being hooked using Infinity hook. It is
very simular to vmcall's dxgkrnl_hook. The code is by no means pretty. Maybe someone will find this useful but I don't recommend using this. 
As we are hooking NtGdiDdDDISubmitCommand, we are perfectly in sync with the screen update according to vmcall's writeup. However, since we are intercepting
it to draw our stuff, it will delay the call and cause lag. 

This is tested on Windows 1903 with kdmapper.

# Features (GDI functions)
NtUserGetDC  
NtGdiSelectBrush  
NtGdiPatBlt  
NtUserReleaseDC  
NtGdiCreateSolidBrush  
NtGdiDeleteObjectApp  
NtGdiExtTextOutW  
NtGdiHfontCreate  
NtGdiSelectFont  
Adding new GDI function to this project is quite easy. Just go to reactos to search for the function args to create the typedef and search for the symbols in windbg. 
Alternatively, you can open win32kbase, win32k, win32kfull in IDA and search for the exported symbols and create the typedef. 

# Credits
Vmcall - Structs, typedef, reference and gdi functions. (https://github.com/vmcall/dxgkrnl_hook)  
         The main idea is originated from his repository: dxgkrnl_hook. I couldn't get his project to work so I created my won.  
everdox - Infinity hook (https://github.com/everdox/InfinityHook)  
Reactos - Structs, typedef, reference and gdi functions  
shixiaoyi - Structs, typedef, reference and gdi functions (https://www.unknowncheats.me/forum/c-and-c-/330328-kernelgdi.html)  

