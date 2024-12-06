/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2024
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
 * @file sesexec_discover.c
 * @brief Declare functionality associated with sesman restart support
 * @author Matt Burt
 *
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "sesexec_discover.h"

/******************************************************************************/
int
sesexec_discover_enable(void)
{
    return 0;
}

/******************************************************************************/

int
sesexec_discover_disable(void)
{
    return 0;
}

/******************************************************************************/

int
sesexec_discover_get_wait_objs(intptr_t robjs[], int *robjs_count,
                               int max_count)
{
    return 0;
}

/******************************************************************************/

int
sesexec_discover_check_wait_objs(void)
{
    return 0;
}
