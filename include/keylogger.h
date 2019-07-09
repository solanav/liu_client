#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#define SHM_KEYLOGGER "/sm_keylogger"

/**
 * Inits the keylogger
 *
 * Returns - OK or ERROR
*/
int keylogger_init();

/**
 * allows the keylogger to works 
 *
 * Returns - OK or ERROR
*/
void keylogger_allow();

/**
 * deny the keylogger to works
 *
 * Returns - OK or ERROR
*/
void keylogger_deny();

/**
 * ends the keylogger
 *
 * Returns - OK or ERROR
*/
void keylogger_end();

#endif
