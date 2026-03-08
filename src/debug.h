/* ═══════════════════════════════════════════════════════════════════════════
 * openuf - debug.h   Sistema de logs por niveles, con control en compilación.
 *
 * NIVELES  (OPENUF_LOG_LEVEL):
 *   0  SILENT  — sin salida alguna
 *   1  ERROR   — solo errores graves
 *   2  WARN    — errores + avisos
 *   3  INFO    — (por defecto en producción) resumen de operaciones
 *   4  DEBUG   — trazas detalladas por módulo
 *   5  TRACE   — todo: bucles internos, dumps hex, lecturas de /proc
 *
 * CÓMO COMPILAR:
 *   Por defecto (producción)                          →  nivel 3  (INFO)
 *   make DEBUG=1  /  make -f Makefile.standalone DEBUG=1  →  nivel 4  (DEBUG)
 *   make TRACE=1                                      →  nivel 5  (TRACE)
 *   make LOG_LEVEL=2                                  →  nivel personalizado
 *
 *   En el SDK de OpenWrt:
 *     make package/openuf/compile DEBUG=1
 *     make package/openuf/compile TRACE=1
 *
 * MACROS DE USO:
 *   LOG_ERR(fmt, ...)    siempre visible (nivel >= 1)
 *   LOG_WARN(fmt, ...)   nivel >= 2
 *   LOG_INFO(fmt, ...)   nivel >= 3
 *   LOG_DBG(fmt, ...)    nivel >= 4  (solo con DEBUG=1)
 *   LOG_TRACE(fmt, ...)  nivel >= 5  (solo con TRACE=1)
 *   DBG_HEX(label, buf, len)   vuelca hasta 64 bytes en hex (nivel >= 5)
 *   debug_print_level()  imprime el nivel activo al arrancar
 *
 * REQUISITO POR MÓDULO:
 *   Cada .c que use estas macros debe definir DBG_TAG antes de incluir debug.h:
 *     #define DBG_TAG "announce"
 *
 * Cuando el nivel es suficientemente bajo el compilador elimina completamente
 * el código de las macros desactivadas — cero overhead en producción.
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifndef OPENUF_DEBUG_H
#define OPENUF_DEBUG_H

#include <stdio.h>
#include <time.h>

/* ─── Resolución del nivel activo ──────────────────────────────────────── */
/* Prioridad: LOG_LEVEL explícito > TRACE > DEBUG > defecto (INFO=3)        */

#ifndef OPENUF_LOG_LEVEL
#  ifdef  OPENUF_TRACE     /* make TRACE=1  →  todos los logs          */
#    define OPENUF_LOG_LEVEL 5
#  elif   defined(OPENUF_DEBUG) /* make DEBUG=1  →  DBG + niveles bajos */
#    define OPENUF_LOG_LEVEL 4
#  else                    /* producción por defecto: solo INFO+        */
#    define OPENUF_LOG_LEVEL 3
#  endif
#endif

/* ─── Timestamp compacto HH:MM:SS ─────────────────────────────────────── */
static inline void _log_ts(void)
{
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    fprintf(stderr, "%02d:%02d:%02d ", tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/* ─── Etiqueta de nivel ────────────────────────────────────────────────── */
static inline const char *_log_lvlname(int l)
{
    switch (l) {
        case 1: return "ERR  ";
        case 2: return "WARN ";
        case 3: return "INFO ";
        case 4: return "DBG  ";
        case 5: return "TRACE";
        default: return "?    ";
    }
}

/* ─── Macro interna genérica ───────────────────────────────────────────── */
/* Se evalúa sólo si el nivel activo >= lvl. El compilador elimina         */
/* completamente las ramas de nivel superior (dead code elimination).       */
#define _LOG(lvl, fmt, ...) do {                                    \
    if ((lvl) <= OPENUF_LOG_LEVEL) {                                \
        _log_ts();                                                   \
        fprintf(stderr, "[%s %-8s] " fmt "\n",                      \
                _log_lvlname(lvl),                                   \
                DBG_TAG,                                             \
                ##__VA_ARGS__);                                      \
        fflush(stderr);                                             \
    }                                                               \
} while (0)

/* ─── Macros públicas ──────────────────────────────────────────────────── */
/* El compilador descarta completamente las macros cuyo nivel supera el    */
/* OPENUF_LOG_LEVEL activo: cero coste en producción.                      */

#define LOG_ERR(fmt, ...)   _LOG(1, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  _LOG(2, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  _LOG(3, fmt, ##__VA_ARGS__)
#define LOG_DBG(fmt, ...)   _LOG(4, fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...) _LOG(5, fmt, ##__VA_ARGS__)

/* ─── Volcado hex (activo solo a nivel TRACE) ──────────────────────────── */
static inline void _dbg_hex(const char *tag, const char *label,
                             const unsigned char *buf, int len)
{
#if OPENUF_LOG_LEVEL >= 5
    _log_ts();
    fprintf(stderr, "[TRACE %-8s] HEX %s (%d bytes):", tag, label, len);
    for (int _i = 0; _i < len && _i < 64; _i++) {
        if (_i % 16 == 0) fprintf(stderr, "\n  ");
        fprintf(stderr, "%02x ", buf[_i]);
    }
    if (len > 64) fprintf(stderr, "\n  ... (%d bytes más)", len - 64);
    fprintf(stderr, "\n");
    fflush(stderr);
#else
    (void)tag; (void)label; (void)buf; (void)len;
#endif
}

#define DBG_HEX(label, buf, len) \
    _dbg_hex(DBG_TAG, label, (const unsigned char *)(buf), (int)(len))

/* ─── Compatibilidad con código antiguo (DLOG / DLOG_HEX) ─────────────── */
/* Redirigen al nivel DBG y TRACE respectivamente. No usar en código nuevo. */
#define DLOG(fmt, ...)          LOG_DBG(fmt, ##__VA_ARGS__)
#define DLOG_HEX(label, buf, n) DBG_HEX(label, buf, n)

/* ─── Función de diagnóstico al arranque ───────────────────────────────── */
#ifndef DBG_TAG
#  define DBG_TAG "?"
#endif

static inline void debug_print_level(void)
{
#if   OPENUF_LOG_LEVEL == 0
    /* silencio total — sin output */
#elif OPENUF_LOG_LEVEL == 1
    fprintf(stderr, "openuf: log nivel 1 (ERROR)\n");
#elif OPENUF_LOG_LEVEL == 2
    fprintf(stderr, "openuf: log nivel 2 (WARN)\n");
#elif OPENUF_LOG_LEVEL == 3
    /* producción — sin banner de debug */
#elif OPENUF_LOG_LEVEL == 4
    fprintf(stderr, "openuf: *** DEBUG activo (nivel 4) ***"
                    "  — compilar sin DEBUG=1 para producción\n");
#else
    fprintf(stderr, "openuf: *** TRACE activo (nivel 5) ***"
                    "  — máxima verbosidad, alto volumen de logs\n");
#endif
    fflush(stderr);
}

#endif /* OPENUF_DEBUG_H */
