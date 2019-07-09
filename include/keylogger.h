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
 * Allows the keylogger to works 
 * 
 * Puts the flag capture to 1. Only works if keylogger has been initialized
 *
 * Returns - OK or ERROR
*/
void keylogger_allow();

/**
 * Deny the keylogger to works
 * 
 * Puts the flag capture to 0. Only works if keylogger has been initialized
 *
 * Returns - OK or ERROR
*/
void keylogger_deny();

/**
 * Ends the keylogger
 * 
 * End the keylogging proccess. Only works if the keylogger has been initialized.
 *
 * Returns - OK or ERROR
*/
void keylogger_end();

#endif
