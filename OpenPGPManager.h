/*
 * WherzatPGP.h
 *
 *  Created on: Jul 8, 2019
 *      Author: novel
 */

#ifndef OPENPGPMANAGER_H_
#define OPENPGPMANAGER_H_

#include "OpenPGP.h"

class OpenPGPManager {
public:
	OpenPGPManager();
	virtual ~OpenPGPManager();

	bool readPublicKey(const std::string& pubPath, std::string& outMsg, std::string& outErrMsg) const;
	bool readSecretKey(const std::string& secPath, std::string& outMsg, std::string& outErrMsg) const;

	bool decryptMsg(const std::string& secPath, const std::string& passphrase, const std::string& data, std::string& outMsg, std::string& outErrMsg) const;
	bool encryptMsg(const std::string& pubPath, const std::string& data, std::string& outMsg, std::string& outErrMsg) const;

	bool signMsg(const std::string& secPath, const std::string& passphrase, const std::string& data, std::string& outMsg, std::string& outErrMsg) const;
	bool verifyMsg(const std::string& pubKey, const std::string& data, const std::string& sigData, std::string& outErrMsg) const;

	bool getFingerprint(const std::string& pubKey, std::string& outFingerprint, std::string& outErrMsg) const;

private:
	OpenPGP::SecretKey loadSecretKey(const std::string& secPath) const;
	OpenPGP::PublicKey loadPublicKey(const std::string& pubPath) const;
};

#endif /* OPENPGPMANAGER_H_ */
