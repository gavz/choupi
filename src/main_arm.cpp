/*
** The MIT License (MIT)
**
** Copyright (c) 2020, National Cybersecurity Agency of France (ANSSI)
**
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the "Software"), to deal
** in the Software without restriction, including without limitation the rights
** to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
** copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions:
**
** The above copyright notice and this permission notice shall be included in
** all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
**
** Author:
**   - Guillaume Bouffard <guillaume.bouffard@ssi.gouv.fr>
*/

#ifndef PC_VERSION

#include "debug.hpp"
#include "ffi.h"
#include "interpretor.hpp"
#include "jc_config.h"
#include "jni.hpp"
#include "types.hpp"

// Based on STMicroelectronics template, see license there

#include "stm32f4xx_hal.h"
#include <ctype.h>
#include <errno.h>
#include <reent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reent.h>
#include <unistd.h>

static void SystemClock_Config(void);
extern "C" void Error_Handler(void);

static UART_HandleTypeDef huart;

#ifdef STM32F401xE

// Nucleo-f401re
#include "stm32f401xe.h"
#define USART USART2
#define BUTTON_PORT GPIOC
#define BUTTON_PORT_NUM 2 // ord(C) - ord(A)
#define BUTTON_GPIO 13    // PC13
#define BUTTON_IRQHANDLER EXTI15_10_IRQHandler
#define BUTTON_INTERRUPT_NUM 40 // number of BUTTON_IRQHANDLER in isrvec
#define IRQNUM (1 << BUTTON_GPIO)
#define LED_PORT GPIOA
#define LED_PORT_NUM 0 // ord(A) - ord(A)
#define LED_GPIO 5     // PA5
#define USART_RX GPIO_PIN_2
#define USART_TX GPIO_PIN_3
#define USART_ALT GPIO_AF7_USART2
#define USART_CLK_ENABLE() __USART2_CLK_ENABLE()
#define USART_PORT GPIOA
#define USART_PORT_NUM 0 // ord(A) - ord(A)

#elif defined(STM32F429xx)

// stm32f429i-disc1
#include "stm32f429xx.h"
#define USART USART2
#define BUTTON_PORT GPIOA
#define BUTTON_PORT_NUM 0
#define BUTTON_GPIO 0
#define BUTTON_IRQHANDLER EXTI0_IRQHandler
#define BUTTON_INTERRUPT_NUM 6
#define IRQNUM (1 << 0)
#define LED_PORT GPIOG
#define LED_PORT_NUM 6
#define LED_GPIO 13
#define USART_RX GPIO_PIN_2
#define USART_TX GPIO_PIN_3
#define USART_ALT GPIO_AF7_USART2
#define USART_CLK_ENABLE() __USART2_CLK_ENABLE()
#define USART_PORT GPIOA
#define USART_PORT_NUM 0 // ord(A) - ord(A)

#else
#error "Unknown architecture"
#endif

/********\
|* GPIO *|
\********/

// Enables clock on port `port`
#define PORT_ENABLE(port) (RCC->AHB1ENR |= (1 << (port)))

extern "C" void gpio_configure(GPIO_TypeDef *port, int gpio, int moder,
                               int otyper, int ospeedr, int pupdr) {
  uint32_t tmp;
  // Configure MODER as output
  tmp = port->MODER;
  tmp &= ~(3 << (gpio * 2));  // 3 is 0b11, reset MODER for the gpio
  tmp |= moder << (gpio * 2); // Output is 0b01
  port->MODER = tmp;
  // Configure OTYPER = 0
  tmp = port->OTYPER;
  tmp &= ~(1 << gpio);
  tmp |= (otyper << gpio);
  port->OTYPER = tmp;
  // Configure PUPDR = 0b00
  tmp = port->PUPDR;
  tmp &= ~(3 << (gpio * 2));
  tmp |= (pupdr << (gpio * 2));
  port->PUPDR = tmp;
  // Configure OSPEEDR = 0b11 (maximal speed)
  tmp = port->OSPEEDR;
  tmp &= ~(3 << (gpio * 2));
  tmp |= (ospeedr << (gpio * 2));
  port->OSPEEDR = tmp;
}

// Configures gpio `gpio` of port `port` as output push-pull max-speed
void gpio_configure_out(GPIO_TypeDef *port, int gpio) {
  gpio_configure(port, gpio, 1, 0, 3, 0);
}

// Configures gpio `gpio` of port `port` as input floating
void gpio_configure_in(GPIO_TypeDef *port, int gpio) {
  gpio_configure(port, gpio, 0, 0, 0, 0);
}

// Toggles a gpio output
void gpio_toggle(GPIO_TypeDef *port, int gpio) { port->ODR ^= (1 << gpio); }

// Sets a gpio output
void gpio_set(GPIO_TypeDef *port, int gpio, int val) {
  uint32_t tmp = port->ODR;
  tmp &= ~((!val) << gpio);
  tmp |= ((!!val) << gpio);
  port->ODR = tmp;
}

// Gets a gpio input
int gpio_get(GPIO_TypeDef *port, int gpio) {
  return (port->IDR & (1 << gpio)) >> gpio;
}

/**************\
|* Interrupts *|
\**************/

// `port` is 0 for PA, 1 for PB, 2 for PC, 3 for PD, 4 for PE, 5 for PF, 6 for
// PG, 7 for PH and 8 for PI
void interrupt_enable(int port, int num, int interrupt, int onrising,
                      int onfalling) {
  uint32_t tmp;
  // Enable SYSCFG (1 << 14 is SYSCFG)
  RCC->APB2ENR |= (1 << 14);
  RCC->APB2RSTR |= (1 << 14);
  RCC->APB2RSTR &= ~(1 << 14);
  // Limit interrupt to specific port
  tmp = SYSCFG->EXTICR[num >> 2];
  tmp &= ~(0xF << ((num & 3) << 2));
  tmp |= (port << ((num & 3) << 2));
  SYSCFG->EXTICR[num >> 2] = tmp;
  // Enable rising edge detection
  tmp = EXTI->RTSR;
  tmp &= ~((!onrising) << num);
  tmp |= ((!!onrising) << num);
  EXTI->RTSR = tmp;
  // Enable falling edge detection
  tmp = EXTI->FTSR;
  tmp &= ~((!onfalling) << num);
  tmp |= ((!!onfalling) << num);
  EXTI->FTSR = tmp;
  // Enable interrupt
  EXTI->IMR |= (1 << num);
  // Unmask interrupt
  NVIC->ISER[interrupt >> 5] |= (1 << (interrupt & 31));
}

void BUTTON_IRQHANDLER() {
  if (EXTI->PR & IRQNUM) {
    gpio_toggle(LED_PORT, LED_GPIO);
    EXTI->PR |= IRQNUM; // Clear interrupt
  }
}

/********\
|* UART *|
\********/

extern "C" void uart_init() {
  PORT_ENABLE(USART_PORT_NUM);
  huart.Instance = USART;
  huart.Init.BaudRate = 38400;
  huart.Init.WordLength = UART_WORDLENGTH_8B;
  huart.Init.StopBits = UART_STOPBITS_1;
  huart.Init.Parity = UART_PARITY_NONE;
  huart.Init.Mode = UART_MODE_TX_RX;
  huart.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart.Init.OverSampling = UART_OVERSAMPLING_16;
  HAL_UART_Init(&huart);
}

extern "C" void HAL_UART_MspInit(UART_HandleTypeDef *huart) {
  GPIO_InitTypeDef GPIO_InitStruct;

  if (huart->Instance == USART) {
    USART_CLK_ENABLE();

    GPIO_InitStruct.Pin = USART_RX | USART_TX;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_LOW;
    GPIO_InitStruct.Alternate = USART_ALT;
    HAL_GPIO_Init(USART_PORT, &GPIO_InitStruct);
  }
}

extern "C" void usart_write(char *ptr, int len) {
  HAL_UART_Transmit(&huart, (uint8_t *)ptr, len, HAL_MAX_DELAY);
}

extern "C" int _read(int file, char *ptr, int len) {
  if (file != STDIN_FILENO) {
    errno = EBADF;
    return -1;
  }

  char c;
  int i = 0;

  while (i < len) {
    HAL_UART_Receive(&huart, (uint8_t *)&c, 1, HAL_MAX_DELAY);

    if (c == '\r') {
      HAL_UART_Transmit(&huart, (uint8_t *)"\r\n", 2, HAL_MAX_DELAY);
      ptr[i] = '\n';
      return i + 1;
    } else if (c == 0x7F) { // backspace
      if (i != 0) {
        HAL_UART_Transmit(&huart, (uint8_t *)"\b \b", 3, HAL_MAX_DELAY);
        --i;
      }
    } else if (isalnum((int)c) || c == ' ') {
      HAL_UART_Transmit(&huart, (uint8_t *)&c, 1, HAL_MAX_DELAY);
      ptr[i] = c;
      ++i;
    }
  }

  return len;
}

/**************\
 * Rust calls *
\**************/

extern "C" void heap_init();
extern "C" void mpu_init_javacard();
extern "C" void fs_dump();

extern "C" int starting_jcre();

extern "C" uint8_t mpu_shared_ro_size;
extern "C" uint8_t mpu_shared_ro_start;
extern "C" uint8_t mpu_shared_rw_size;
extern "C" uint8_t mpu_shared_rw_start;
extern "C" uint8_t mpu_shared_rw_start_to_clean;

void jcvm_terminate() {
  while (1) {
  }
}

void jcvm_unexpected() {
  while (1) {
  }
}

int main_arm(void) {

  std::set_terminate(jcvm_terminate);
  std::set_unexpected(jcvm_unexpected);

  // FIRST, ZERO-OUT SHARED_RO AND SHARED_RW (as it's not in .data)
  size_t i;

  for (i = 0; i < (size_t)&mpu_shared_ro_size; ++i) {
    (&mpu_shared_ro_start)[i] = 0;
  }

  for (i = (&mpu_shared_rw_start_to_clean - &mpu_shared_rw_start);
       i < (size_t)&mpu_shared_rw_size; ++i) {
    (&mpu_shared_rw_start)[i] = 0;
  }

  //  Set the first mpu_shared_rw_start as location of _impure_ptr
  /*
 struct _reent *init_reent =
     (((struct _reent *)(&mpu_shared_rw_start + 0x0c)));

 init_reent->_stdin = _REENT->_stdin;
 init_reent->_stdout = _REENT->_stdout;
 init_reent->_stderr = _REENT->_stderr;

 _impure_ptr = init_reent; */

  /* STM32F4xx HAL library initialization:
       - Configure the Flash prefetch, Flash preread and Buffer caches
       - Systick timer is configured by default as source of time base, but user
           can eventually implement his proper time base source (a general
     purpose timer for example or other time source), keeping in mind that Time
     base duration should be kept 1ms since PPP_TIMEOUT_VALUEs are defined and
           handled in milliseconds basis.
       - Low Level Initialization
   */
  HAL_Init();

  /* Configure the System clock to 84 MHz */
  SystemClock_Config();

  /* Configure PA05 IO in output push-pull mode to drive external LED */
  PORT_ENABLE(LED_PORT_NUM);
  gpio_configure_out(LED_PORT, LED_GPIO);

  PORT_ENABLE(BUTTON_PORT_NUM);
  gpio_configure_in(BUTTON_PORT, BUTTON_GPIO);
  interrupt_enable(BUTTON_PORT_NUM, BUTTON_GPIO, BUTTON_INTERRUPT_NUM, 0, 1);

  uart_init();

  heap_init();

  if (fs_init()) {
    TRACE_JCVM_ERR("FAILED TO INITIALIZE FS DRIVER\r\n");
  }

  setup_argbuf();

  mpu_init_javacard();

  // Starting Java Card Runtime Environement.
  remote_call(0, 0, 0);

  while (1) {
    ;
  }
}

/**
 * System Clock Configuration
 *   The system Clock is configured as follow :
 *      System Clock source            = PLL (HSI)
 *      SYSCLK(Hz)                     = 84000000
 *      HCLK(Hz)                       = 84000000
 *      AHB Prescaler                  = 1
 *      APB1 Prescaler                 = 2
 *      APB2 Prescaler                 = 1
 *      HSI Frequency(Hz)              = 16000000
 *      PLL_M                          = 16
 *      PLL_N                          = 336
 *      PLL_P                          = 4
 *      PLL_Q                          = 7
 *      VDD(V)                         = 3.3
 *      Main regulator output voltage  = Scale2 mode
 *      Flash Latency(WS)              = 2
 */
static void SystemClock_Config(void) {
  RCC_ClkInitTypeDef RCC_ClkInitStruct;
  RCC_OscInitTypeDef RCC_OscInitStruct;
  HAL_StatusTypeDef status;

  /* Enable Power Control clock */
  __PWR_CLK_ENABLE();

  /* The voltage scaling allows optimizing the power consumption when the device
     is clocked below the maximum system frequency, to update the voltage
     scaling value regarding system frequency refer to product datasheet.  */
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE2);

  /* Enable HSI Oscillator and activate PLL with HSI as source */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = 0x10;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 16;
  RCC_OscInitStruct.PLL.PLLN = 336;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV4;
  RCC_OscInitStruct.PLL.PLLQ = 7;

  if ((status = HAL_RCC_OscConfig(&RCC_OscInitStruct)) != HAL_OK) {
    Error_Handler();
  }

  /* Select PLL as system clock source and configure the HCLK, PCLK1 and PCLK2
     clocks dividers */
  RCC_ClkInitStruct.ClockType = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK |
                                 RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2);
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK) {
    Error_Handler();
  }
}

extern "C" void Error_Handler(void) {
  volatile uint32_t x;

  while (1) {
    gpio_toggle(LED_PORT, LED_GPIO);

    for (x = 0; x < 0xFFFFF; ++x)
      ;
  }
}

//  The runtime_main function is called in the context 0.
extern "C" int starting_jcre() {

  TRACE_JCVM_DEBUG("Starting JCRE");

  // Call GP applet => main security domain
  uint32_t arg = (STARTING_JAVACARD_PACKAGE << 16) |
                 (STARTING_JAVACARD_CLASS << 8) | (STARTING_JAVACARD_METHOD);
  remote_call(2, arg, 0);

  return 0;
}

namespace __gnu_cxx {

void __verbose_terminate_handler() {
  for (;;)
    ;
}
} // namespace __gnu_cxx

extern "C" void __cxa_pure_virtual() {
  for (;;)
    ;
}

#endif /* !PC_VERSION */
