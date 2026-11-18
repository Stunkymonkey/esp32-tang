#pragma once
// Host stand-in: PBKDF2 yields with vTaskDelay(); on the host it need not.
inline void vTaskDelay(int) {}
