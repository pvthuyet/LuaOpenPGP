/*
 * LuaOpenPGP.cpp
 *
 *  Created on: Jul 8, 2019
 *      Author: novel
 */

#include "OpenPGPManager.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <lua.h>                               /* Always include this */
#include <lauxlib.h>                           /* Always include this */
#include <lualib.h>                            /* Always include this */

static int idecryptMsg(lua_State *L) {
	const char *secPath = lua_tostring(L, 1);
	const char *passphrase = lua_tostring(L, 2);
	const char *data = lua_tostring(L, 3);

	OpenPGPManager mgr;
	std::string outMsg;
	std::string outErrMsg;
	int result = mgr.decryptMsg(secPath, passphrase, data, outMsg, outErrMsg);

	lua_pushnumber(L,result);      /* Push the return */
	lua_pushstring(L, outMsg.c_str());
	lua_pushstring(L, outErrMsg.c_str());

	return 3;                      /* Three return value */
}

static int iencryptMsg(lua_State *L) {
	const char *pubPath = lua_tostring(L, 1);
	const char *data = lua_tostring(L, 2);

	OpenPGPManager mgr;
	std::string outMsg;
	std::string outErrMsg;
	int result = mgr.encryptMsg(pubPath, data, outMsg, outErrMsg);

	lua_pushnumber(L,result);      /* Push the return */
	lua_pushstring(L, outMsg.c_str());
	lua_pushstring(L, outErrMsg.c_str());

	return 3;                      /* Three return value */
}

static int ireadPublicKey(lua_State *L) {
	const char *pubPath = lua_tostring(L, 1);

	OpenPGPManager mgr;
	std::string outMsg;
	std::string outErrMsg;
	int result = mgr.readPublicKey(pubPath, outMsg, outErrMsg);
	lua_pushnumber(L,result);      /* Push the return */
	lua_pushstring(L, outMsg.c_str());
	lua_pushstring(L, outErrMsg.c_str());

	return 3;                      /* Three return value */
}

static int ireadSecretKey(lua_State *L) {
	const char *secPath = lua_tostring(L, 1);

	OpenPGPManager mgr;
	std::string outMsg;
	std::string outErrMsg;
	int result = mgr.readSecretKey(secPath, outMsg, outErrMsg);
	lua_pushnumber(L,result);      /* Push the return */
	lua_pushstring(L, outMsg.c_str());
	lua_pushstring(L, outErrMsg.c_str());

	return 3;                      /* Three return value */
}

static int isignMsg(lua_State *L) {
	const char *secPath = lua_tostring(L, 1);
	const char *passphrase = lua_tostring(L, 2);
	const char *data = lua_tostring(L, 3);

	OpenPGPManager mgr;
	std::string outMsg;
	std::string outErrMsg;
	int result = mgr.signMsg(secPath, passphrase, data, outMsg, outErrMsg);

	lua_pushnumber(L,result);      /* Push the return */
	lua_pushstring(L, outMsg.c_str());
	lua_pushstring(L, outErrMsg.c_str());

	return 3;                      /* Three return value */
}

static int iverifyMsg(lua_State *L) {
	const char *pubKey = lua_tostring(L, 1);
	const char *data = lua_tostring(L, 2);
	const char *sigData = lua_tostring(L, 3);

	OpenPGPManager mgr;
	std::string outErrMsg;
	int result = mgr.verifyMsg(pubKey, data, sigData, outErrMsg);

	lua_pushnumber(L,result);      /* Push the return */
	lua_pushstring(L, outErrMsg.c_str());

	return 2;                      /* One return value */
}

static int igetFingerprint(lua_State *L) {
        const char *pubKey = lua_tostring(L, 1);

        OpenPGPManager mgr;
	std::string fingerprint;
        std::string outErrMsg;
        int result = mgr.getFingerprint(pubKey, fingerprint, outErrMsg);

        lua_pushnumber(L,result);      /* Push the return */
	lua_pushstring(L, fingerprint.c_str());
        lua_pushstring(L, outErrMsg.c_str());

        return 3;                      /* One return value */
}


/* Register this file's functions with the
 * luaopen_libraryname() function, where libraryname
 * is the name of the compiled .so output. In other words
 * it's the filename (but not extension) after the -o
 * in the cc command.
 *
 * So for instance, if your cc command has -o LuaOpenPGP.so then
 * this function would be called luaopen_power().
 *
 * This function should contain lua_register() commands for
 * each function you want available from Lua.
 *
*/
int luaopen_LuaOpenPGP(lua_State *L){
	lua_register(L,"decryptMsg",idecryptMsg);
	lua_register(L,"encryptMsg",iencryptMsg);
	lua_register(L,"readPublicKey",ireadPublicKey);
	lua_register(L,"readSecretKey",ireadSecretKey);
	lua_register(L,"signMsg",isignMsg);
	lua_register(L,"verifyMsg",iverifyMsg);
        lua_register(L,"getFingerprint",igetFingerprint);

	return 0;
}

#ifdef __cplusplus
}
#endif
