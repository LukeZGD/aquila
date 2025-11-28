#ifndef screen_h
#define screen_h

#include "common.h"

typedef kern_return_t IOReturn;
typedef IOReturn IOMobileFramebufferReturn;
typedef struct __IOMobileFramebuffer *IOMobileFramebufferRef;
typedef CGSize IOMobileFramebufferDisplaySize;

extern IOReturn IOMobileFramebufferGetMainDisplay(IOMobileFramebufferRef *);
extern IOReturn IOMobileFramebufferGetDisplaySize(IOMobileFramebufferRef, IOMobileFramebufferDisplaySize *);
extern IOReturn IOMobileFramebufferGetLayerDefaultSurface(IOMobileFramebufferRef, int, IOSurfaceRef *);
extern IOReturn IOMobileFramebufferSwapBegin(IOMobileFramebufferRef, int *);
extern IOReturn IOMobileFramebufferSwapEnd(IOMobileFramebufferRef);
extern IOReturn IOMobileFramebufferSwapSetLayer(IOMobileFramebufferRef, int, IOSurfaceRef, CGRect, CGRect, int);

int draw_splash_screen(const char *path);

#endif /* screen_h */