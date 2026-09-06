/*
 * GridHawk demo transmitter -- unmodulated carrier on an RFM69HCW.
 *
 * Board: Adafruit Feather M0 RadioFruit RFM69HCW (433 MHz version)
 *
 * WHY A BARE CARRIER
 * ------------------
 * The demo measures the FREQUENCY of a transmitter, not the data it sends.
 * A modulated signal smears its energy across a band and has no single line to
 * measure. Putting the radio into continuous mode with no data leaves a pure
 * tone, whose frequency can be measured to within a few hundred hertz.
 *
 * WHY THIS TALKS TO REGISTERS DIRECTLY
 * ------------------------------------
 * Packet libraries (RadioHead and friends) have no "transmit a bare carrier"
 * function, because no normal application wants one. Driving the chip directly
 * is about sixty lines and avoids depending on library internals.
 *
 * THE POINT OF THE DEMO
 * ---------------------
 * Flash this to BOTH boards with the SAME nominal frequency. They will still
 * transmit on measurably different frequencies, because each board's crystal
 * has its own manufacturing error. That difference is the fingerprint.
 *
 * SERIAL COMMANDS (115200 baud)
 * -----------------------------
 *   t          toggle transmit on/off
 *   p <0-31>   set power level, 0 is lowest
 *   o <ppm>    offset the frequency by this many ppm (for calibration checks)
 *   f <hz>     set the nominal frequency
 *   ?          print current settings
 */

#include <SPI.h>

// ---- Feather M0 RadioFruit pin assignments ------------------------------
const int PIN_RFM_CHIP_SELECT = 8;
const int PIN_RFM_RESET       = 4;
const int PIN_RFM_INTERRUPT   = 3;
const int PIN_STATUS_LED      = 13;

// ---- RFM69 registers we touch -------------------------------------------
const uint8_t REG_OPERATING_MODE = 0x01;
const uint8_t REG_DATA_MODULATION = 0x02;
const uint8_t REG_FREQUENCY_DEVIATION_MSB = 0x05;   // 0x05..0x06, 16-bit
const uint8_t REG_FREQUENCY_MSB  = 0x07;   // 0x07..0x09 hold a 24-bit value
const uint8_t REG_PA_LEVEL       = 0x11;
const uint8_t REG_VERSION        = 0x10;

// Operating mode: bits 4..2 select the mode.
const uint8_t MODE_STANDBY  = 0x01 << 2;
const uint8_t MODE_TRANSMIT = 0x03 << 2;

// Data mode "continuous, no bit synchroniser" (0b11) with FSK and no shaping.
// With nothing driving the data input this produces a steady carrier.
const uint8_t DATA_MODE_CONTINUOUS_NO_SYNC = 0x60;

// The RFM69HCW has no PA0 pin connected, so PA1 must be enabled (bit 6).
const uint8_t PA_LEVEL_PA1_ENABLED = 0x40;

// Frequency deviation of zero. In FSK the radio shifts between two frequencies
// according to its data input; with a deviation of zero those two frequencies
// are the same one, so the output collapses to a single unmodulated tone.
//
// This matters more than it sounds. Left at the chip default, and with nothing
// driving the data input, the radio hops randomly between two frequencies and
// smears its energy across the band. A spectrum sweep then shows a raised noise
// floor and NO peak -- which looks exactly like a transmitter that is not
// working, when in fact it is transmitting the wrong shape of signal.
const uint8_t ZERO_DEVIATION = 0x00;

// The radio derives its frequency from a 32 MHz crystal divided by 2^19.
// Every frequency we ask for is rounded to a multiple of this step.
const double FREQUENCY_STEP_HZ = 32000000.0 / 524288.0;   // ~61.035 Hz

// ---- Defaults ------------------------------------------------------------
// Flash BOTH boards with this same value. Do not "correct" one of them --
// the difference between them is the whole experiment.
double nominalFrequencyHz = 433920000.0;

// Deliberate offset, used to check the detector reports a ppm figure you
// already know. Leave at 0 for the real measurement.
double frequencyOffsetPpm = 0.0;

// Keep this LOW. A transmitter close to the receiver will overload its front
// end and create spurious signals the detector will faithfully report as
// extra radios.
uint8_t powerLevel = 0;

bool transmitting = false;

SPISettings radioSpiSettings(4000000, MSBFIRST, SPI_MODE0);


void writeRadioRegister(uint8_t address, uint8_t value) {
  SPI.beginTransaction(radioSpiSettings);
  digitalWrite(PIN_RFM_CHIP_SELECT, LOW);
  SPI.transfer(address | 0x80);            // high bit set means "write"
  SPI.transfer(value);
  digitalWrite(PIN_RFM_CHIP_SELECT, HIGH);
  SPI.endTransaction();
}


uint8_t readRadioRegister(uint8_t address) {
  SPI.beginTransaction(radioSpiSettings);
  digitalWrite(PIN_RFM_CHIP_SELECT, LOW);
  SPI.transfer(address & 0x7F);            // high bit clear means "read"
  uint8_t value = SPI.transfer(0);
  digitalWrite(PIN_RFM_CHIP_SELECT, HIGH);
  SPI.endTransaction();
  return value;
}


double effectiveFrequencyHz() {
  return nominalFrequencyHz * (1.0 + frequencyOffsetPpm / 1000000.0);
}


void applyFrequency() {
  // The chip wants the frequency as a count of synthesiser steps.
  uint32_t steps = (uint32_t)(effectiveFrequencyHz() / FREQUENCY_STEP_HZ);
  writeRadioRegister(REG_FREQUENCY_MSB + 0, (steps >> 16) & 0xFF);
  writeRadioRegister(REG_FREQUENCY_MSB + 1, (steps >> 8) & 0xFF);
  writeRadioRegister(REG_FREQUENCY_MSB + 2, steps & 0xFF);
}


void applyZeroDeviation() {
  // Collapse the two FSK tones into one, giving a true carrier.
  writeRadioRegister(REG_FREQUENCY_DEVIATION_MSB + 0, ZERO_DEVIATION);
  writeRadioRegister(REG_FREQUENCY_DEVIATION_MSB + 1, ZERO_DEVIATION);
}


void applyPower() {
  uint8_t level = powerLevel;
  if (level > 31) {
    level = 31;
  }
  writeRadioRegister(REG_PA_LEVEL, PA_LEVEL_PA1_ENABLED | level);
}


void startTransmitting() {
  applyFrequency();
  applyZeroDeviation();
  applyPower();
  writeRadioRegister(REG_DATA_MODULATION, DATA_MODE_CONTINUOUS_NO_SYNC);
  writeRadioRegister(REG_OPERATING_MODE, MODE_TRANSMIT);
  digitalWrite(PIN_STATUS_LED, HIGH);
  transmitting = true;
}


void stopTransmitting() {
  writeRadioRegister(REG_OPERATING_MODE, MODE_STANDBY);
  digitalWrite(PIN_STATUS_LED, LOW);
  transmitting = false;
}


void printSettings() {
  Serial.println(F("--- transmitter settings ---"));
  Serial.print(F("nominal   : ")); Serial.print(nominalFrequencyHz / 1e6, 6); Serial.println(F(" MHz"));
  Serial.print(F("offset    : ")); Serial.print(frequencyOffsetPpm, 3); Serial.println(F(" ppm"));
  Serial.print(F("commanded : ")); Serial.print(effectiveFrequencyHz() / 1e6, 6); Serial.println(F(" MHz"));
  Serial.print(F("power     : ")); Serial.println(powerLevel);
  Serial.print(F("deviation : ")); Serial.print(readRadioRegister(REG_FREQUENCY_DEVIATION_MSB));
  Serial.print(F(" ")); Serial.print(readRadioRegister(REG_FREQUENCY_DEVIATION_MSB + 1));
  Serial.println(F("  (both must be 0 for a clean carrier)"));
  Serial.print(F("state     : "));
  if (transmitting) {
    Serial.println(F("TRANSMITTING"));
  } else {
    Serial.println(F("standby"));
  }
  Serial.println(F("NOTE: the frequency actually radiated differs from the"));
  Serial.println(F("commanded one by this board's own crystal error. That is"));
  Serial.println(F("what the detector measures."));
}


void setup() {
  Serial.begin(115200);
  pinMode(PIN_STATUS_LED, OUTPUT);
  pinMode(PIN_RFM_CHIP_SELECT, OUTPUT);
  digitalWrite(PIN_RFM_CHIP_SELECT, HIGH);
  pinMode(PIN_RFM_INTERRUPT, INPUT);

  // Hardware reset: hold high briefly, then release and let the chip settle.
  pinMode(PIN_RFM_RESET, OUTPUT);
  digitalWrite(PIN_RFM_RESET, HIGH);
  delay(10);
  digitalWrite(PIN_RFM_RESET, LOW);
  delay(10);

  SPI.begin();

  // Give the USB serial port a few seconds to attach, but do not hang forever
  // if the board is running from a battery with no host attached.
  unsigned long startedWaiting = millis();
  while (!Serial && (millis() - startedWaiting) < 3000) {
    delay(10);
  }

  uint8_t version = readRadioRegister(REG_VERSION);
  Serial.print(F("RFM69 version register: 0x"));
  Serial.println(version, HEX);
  if (version != 0x24) {
    Serial.println(F("WARNING: expected 0x24. Check wiring and that this is"));
    Serial.println(F("really a RadioFruit board."));
  }

  writeRadioRegister(REG_OPERATING_MODE, MODE_STANDBY);
  applyFrequency();
  applyZeroDeviation();
  applyPower();

  Serial.println(F("ready -- 't' to transmit, '?' for settings"));
}


void loop() {
  if (!Serial.available()) {
    return;
  }

  char command = Serial.read();

  if (command == 't') {
    if (transmitting) {
      stopTransmitting();
      Serial.println(F("stopped"));
    } else {
      startTransmitting();
      Serial.println(F("transmitting"));
    }
    return;
  }

  if (command == 'p') {
    powerLevel = (uint8_t)Serial.parseInt();
    applyPower();
    Serial.print(F("power -> ")); Serial.println(powerLevel);
    return;
  }

  if (command == 'o') {
    frequencyOffsetPpm = Serial.parseFloat();
    if (transmitting) {
      applyFrequency();
    }
    Serial.print(F("offset -> ")); Serial.print(frequencyOffsetPpm, 3); Serial.println(F(" ppm"));
    return;
  }

  if (command == 'f') {
    double requested = Serial.parseFloat();
    if (requested > 1000000.0) {
      nominalFrequencyHz = requested;
      if (transmitting) {
        applyFrequency();
      }
      Serial.print(F("nominal -> ")); Serial.println(nominalFrequencyHz / 1e6, 6);
    }
    return;
  }

  if (command == '?') {
    printSettings();
  }
}
