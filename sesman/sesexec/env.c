/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2013
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 *
 * @file env.c
 * @brief User environment handling code
 * @author Jay Sorg
 *
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include <grp.h>

#include "env.h"
#include "sesman_config.h"
#include "list.h"
#include "log.h"
#include "os_calls.h"
#include "sesexec.h"
#include "xrdp_sockets.h"

/******************************************************************************/
int
env_set_user(int uid,
             const struct list *env_names, const struct list *env_values)
{
    int error;
    int pw_gid;
    int index;
    char *name;
    char *value;
    char *pw_username = NULL;
    char *pw_shell = NULL;
    char *pw_dir = NULL;
    char *display = NULL;
    int is_x11 = 0;
    char text[256];

    error = g_getuser_info_by_uid(uid, &pw_username, &pw_gid, &pw_shell,
                                  &pw_dir, 0);

    if (error == 0)
    {
        g_rm_temp_dir();
        g_clearenv();
#ifdef HAVE_SETUSERCONTEXT
        error = g_set_allusercontext(uid);
#else
        /* Set some of the things setusercontext() handles on other
         * systems */

        /* Primary group. Note that secondary groups should already
         * have been set, if we're not using setusercontext() */
        error = g_setgid(pw_gid);

        if (error == 0)
        {
            error = g_setuid(uid);
        }

        if (error == 0)
        {
            g_setenv_log("PATH", "/sbin:/bin:/usr/bin:/usr/local/bin", 1);
        }
#endif
        if (error == 0)
        {
            g_setenv_log("SHELL", pw_shell, 1);
            g_setenv_log("USER", pw_username, 1);
            g_setenv_log("LOGNAME", pw_username, 1);
            g_snprintf(text, sizeof(text), "%d", uid);
            g_setenv_log("UID", text, 1);
            g_setenv_log("HOME", pw_dir, 1);
            g_set_current_dir(pw_dir);
            // Use our PID as the XRDP_SESSION value
            g_snprintf(text, sizeof(text), "%d", g_pid);
            g_setenv_log("XRDP_SESSION", text, 1);
            /* XRDP_SOCKET_PATH is used by
             * xorgxrdp and the pulseaudio plugin */
            g_snprintf(text, sizeof(text), XRDP_SOCKET_PATH, uid);
            g_setenv_log("XRDP_SOCKET_PATH", text, 1);

            // Set the passed-in variables. This may include a DISPLAY
            if ((env_names != 0) && (env_values != 0) &&
                    (env_names->count == env_values->count))
            {
                for (index = 0; index < env_names->count; index++)
                {
                    name = (char *) list_get_item(env_names, index),
                    value = (char *) list_get_item(env_values, index),
                    g_setenv_log(name, value, 1);

                    // Look for a DISPLAY. WAYLAND_DISPLAY overrides
                    // DISPLAY
                    if (strcmp(name, "WAYLAND_DISPLAY") == 0)
                    {
                        display = value;
                        is_x11 = 0;
                    }
                    else if (display == NULL && strcmp(name, "DISPLAY") == 0)
                    {
                        display = value;
                        is_x11 = 1;
                    }
                }
            }

            // Set things dependent on the DISPLAY
            if (display != NULL)
            {
                /* pulse sink socket */
                g_snprintf(text, sizeof(text), CHANSRV_PORT_OUT_BASE_STR,
                           display);
                g_setenv_log("XRDP_PULSE_SINK_SOCKET", text, 1);
                /* pulse source socket */
                g_snprintf(text, sizeof(text), CHANSRV_PORT_IN_BASE_STR,
                           display);
                g_setenv_log("XRDP_PULSE_SOURCE_SOCKET", text, 1);

                // Only set Xauthority for X11
                if (is_x11 && g_cfg->sec.xauth_in_sysdir)
                {
                    g_snprintf(text, sizeof(text),
                               XRDP_SOCKET_PATH "/Xauthority", uid);
                    g_setenv_log("XAUTHORITY", text, 1);
                }
            }
        }
    }
    else
    {
        LOG(LOG_LEVEL_ERROR,
            "error getting user info for uid %d", uid);
    }

    g_free(pw_username);
    g_free(pw_dir);
    g_free(pw_shell);

    return error;
}
