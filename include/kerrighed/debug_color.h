#ifndef __DEBUG_COLOR_H__
#define __DEBUG_COLOR_H__

#define RED	31
#define GREEN	32
#define BROWN	33
#define BLUE	34
#define MAGENTA	35
#define CYAN	36
#define WHITE	37

#define STRINGIFY(macro) #macro
#define DEBUG_COLOR(color) "\33[" STRINGIFY(color) "m\r"
#define DEBUG_DIMMED "\33[2m\r"
#define DEBUG_BRIGHT "\33[22m\r"
#define DEBUG_NORMAL "\33[0m\r"

#endif /* __DEBUG_COLOR_H__ */
