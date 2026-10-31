#ifndef OWNED_MODULE_ROLE
#error "OWNED_MODULE_ROLE must be defined"
#endif

#if defined(__GNUC__) || defined(__clang__)
#define OWNED_EXPORT __attribute__((visibility("default")))
#else
#define OWNED_EXPORT
#endif

OWNED_EXPORT const char *owned_module_role(void)
{
    return OWNED_MODULE_ROLE;
}
