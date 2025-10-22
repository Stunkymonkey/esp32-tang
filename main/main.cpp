/*
 * ESP32 Tang Server - ESP-IDF Entry Point
 *
 * This file contains the main entry point (app_main) for the ESP-IDF
 * framework. It initializes and runs the Arduino-based Tang server
 * code in a dedicated FreeRTOS task.
 */
#include <Arduino.h>

// The main header file for the Tang Server application logic.
// This contains the setup() and loop() functions.
#include "TangServer.h"

// Define the task handle for the Arduino loop
TaskHandle_t arduinoTaskHandle = NULL;

#if !CONFIG_AUTOSTART_ARDUINO
/**
 * @brief The FreeRTOS task that will run the Arduino setup and loop.
 * @param pvParameters Unused.
 */
void arduinoTask(void *pvParameters) {
    // Call the Arduino setup function
    setup();

    // Run the Arduino loop function indefinitely
    for (;;) {
        loop();
        // Yield to other tasks
        vTaskDelay(1 / portTICK_PERIOD_MS);
    }
}

/**
 * @brief Main entry point for the ESP-IDF application.
 */
extern "C" void app_main(void) {
    // Initialize the Arduino component. This must be called once.
    initArduino();

    // Create a new FreeRTOS task for the Arduino code.
    // This isolates the Arduino environment and allows it to run alongside
    // other IDF components or tasks.
    xTaskCreate(
      arduinoTask,                    // Function to implement the task
      "arduino_task",                 // Name of the task
      CONFIG_ARDUINO_LOOP_STACK_SIZE, // Stack size in words
      NULL,                           // Task input parameter
      1,                              // Priority of the task
      &arduinoTaskHandle              // Task handle to keep track of the created task
    );
}
#endif
