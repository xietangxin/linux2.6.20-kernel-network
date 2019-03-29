### likely 和 unlikely ###
```
if(likely(value)) 等价于 if(value)
if(unlikely(value)) 等价于 if(value) 
两个宏函数在内核中定义
#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)
```
> 这里的__built_expect()函数是gcc(version >= 2.96)的内建函数,提供给程序员使用的，目的是将"分支转移"的信息提供给编译器，这样编译器对代码进行优化，以减少指令跳转带来的性能下降。  
> __buildin_expect((x), 1)表示x的值为真的可能性更大  
>__buildin_expect((x), 0)表示x的值为假的可能性更大
>**使用likely(),执行if后面的语句的机会更大，使用unlikely(),执行else后面的语句机会更大一些**




