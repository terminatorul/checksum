#include <windows.h>

#include <cstdlib>
#include <memory>
#include <iterator>
#include <tuple>
#include <map>
#include <string>
#include <set>
#include <vector>
#include <iostream>
#include <fstream>
#include <exception>
#include <algorithm>
#include <execution>

#include <Poco/FileStream.h>
#include <Poco/File.h>
#include <Poco/Glob.h>
#include <Poco/MD4Engine.h>
#include <Poco/MD5Engine.h>
#include <Poco/SHA1Engine.h>
#include <Poco/SHA2Engine.h>
#include <Poco/HMACengine.h>
#include <Poco/PBKDF2Engine.h>
#include <Poco/DigestStream.h>

#include "HANDLEStreamBuf.hpp"

using namespace std::literals::string_literals;
using std::cout;
using std::cin;
using std::clog;
using std::cerr;
using std::endl;
using std::istream;
using std::ifstream;
using std::exception;
using std::unique_ptr;
using std::string;
using std::vector;
using std::tuple;
using std::set;
using std::map;
using std::get;
using std::find;
using std::size;
using std::runtime_error;
namespace execution = std::execution;

using Poco::FileInputStream;
using Poco::File;
using Poco::Glob;
using Poco::DigestEngine;
using Poco::MD4Engine;
using Poco::MD5Engine;
using Poco::SHA1Engine;
using Poco::SHA2Engine;
using Poco::SHA2Engine224;
using Poco::SHA2Engine256;
using Poco::SHA2Engine384;
using Poco::SHA2Engine512;
using Poco::HMACEngine;
using Poco::PBKDF2Engine;
using Poco::DigestOutputStream;

#if defined(_WINDOWS)

bool isStdInInteractive()
{
    return GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_CHAR;
}

bool isStdInSeekable()
{
    return GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_DISK;
}

#endif

enum class Digest
{
    None,
    HMAC_MD5,
    HMAC_SHA1,
    HMAC_SHA256,
    MD4,
    MD5,
    PBKDF2_MD5,
    PBKDF2_SHA1,
    PBKDF2_SHA256,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256
};

using DigestSet = vector<tuple<Digest, string>>;

bool ParseCommandLine(vector<tuple<DigestSet, string>> &files, int argc, char *argv[])
{
    unsigned filesCount = 0u;
    DigestSet digestSet;
    string passphrase;

    auto addDigest = [&filesCount, &digestSet, &passphrase](Digest newDigest, string newPassphrase = string())
    {
        if (filesCount)
        {
            filesCount = 0u;
            digestSet.clear();
        }

        auto digest = tuple { newDigest, newPassphrase };

        if (find(execution::par_unseq, digestSet.begin(), digestSet.end(), digest) == digestSet.end())
            digestSet.emplace_back(newDigest, newPassphrase);
    };

    int argIndex = 1;

    while (argIndex < argc)
    {
        char const *arg = argv[argIndex];

        if (arg == "--"s)
        {
            argIndex++;
            break;
        }

        if (arg[0] == '-' && arg[1] != '\0' && arg[1] != '-')
        {
            clog << "Sintax error: unknown option " << arg << "\n\n";
            return false;
        }

        if (arg == "--hmac-md5"s)
        {
            argIndex++;

            if (argIndex >= argc)
            {
                clog << "Sintax error: missing argument for --hmac-md5\n\n";
                return false;
            }
            else
                addDigest(Digest::HMAC_MD5, argv[argIndex++]);

            continue;
        }

        if (arg == "--hmac-sha1"s)
        {
            argIndex++;

            if (argIndex >= argc)
            {
                clog << "Sintax error: missing argument for --hmac-sha1\n\n";
                return false;
            }
            else
                addDigest(Digest::HMAC_SHA1, argv[argIndex++]);

            continue;
        }

        if (arg == "--hmac-sha256"s)
        {
            argIndex++;

            if (argIndex >= argc)
            {
                clog << "Sintax error: missing argument for --hmac-sha256\n\n";
                return false;
            }
            else
                addDigest(Digest::HMAC_SHA256, argv[argIndex++]);

            continue;
        }

        if (arg == "--md4"s)
        {
            addDigest(Digest::MD4);
            argIndex++;
            continue;
        }

        if (arg == "--md5"s)
        {
            addDigest(Digest::MD5);
            argIndex++;
            continue;
        }

        if (arg == "--pbkdf2-md5"s)
        {
            argIndex++;

            if(argIndex >= argc)
            {
                clog << "Sintax error: missing argument for --pbkdf2-md5\n\n";
                return false;
            }
            else
                addDigest(Digest::PBKDF2_MD5, argv[argIndex++]);

            continue;
        }

        if (arg == "--pbkdf2-sha1"s)
        {
            argIndex++;

            if(argIndex >= argc)
            {
                clog << "Sintax error: missing argument for --pbkdf2-sha1\n\n";
                return false;
            }
            else
                addDigest(Digest::PBKDF2_SHA1, argv[argIndex++]);

            continue;
        }

        if (arg == "--pbkdf2-sha256"s)
        {
            argIndex++;

            if(argIndex >= argc)
            {
                clog << "Sintax error: missing argument for --pbkdf2-sha256\n\n";
                return false;
            }
            else
                addDigest(Digest::PBKDF2_SHA256, argv[argIndex++]);

            continue;
        }

        if (arg == "--sha1"s)
        {
            addDigest(Digest::SHA1);
            passphrase.clear();
            argIndex++;
            continue;
        }

        if (arg == "--sha224"s)
        {
            addDigest(Digest::SHA224);
            passphrase.clear();
            argIndex++;
            continue;
        }

        if (arg == "--sha256"s)
        {
            addDigest(Digest::SHA256);
            argIndex++;
            continue;
        }

        if (arg == "--sha384"s)
        {
            addDigest(Digest::SHA384);
            argIndex++;
            continue;
        }

        if (arg == "--sha512"s)
        {
            addDigest(Digest::SHA512);
            argIndex++;
            continue;
        }

        if (arg == "--sha512-224"s)
        {
            addDigest(Digest::SHA512_224);
            argIndex++;
            continue;
        }

        if (arg == "--sha512-256"s)
        {
            addDigest(Digest::SHA512_256);
            argIndex++;
            continue;
        }

        if (arg[0] == '-' && arg[1] == '-' && arg[2] != '\0')
        {
            cerr << "Syntax error: unknown option " << arg << "\n\n";
            return false;
        }

        files.emplace_back(digestSet, arg);
        filesCount++;
        argIndex++;
    }

    while (argIndex < argc)
        files.emplace_back(digestSet, argv[argIndex++]);

    bool hasDefaultDigest = false;
    DigestSet explicitDigest;

    for (auto const &file: files)
    {
        if (get<0>(file).empty())
            hasDefaultDigest = true;
        else
        {
            if (explicitDigest.empty())
                explicitDigest = get<0>(file);
            else
                if (explicitDigest != get<0>(file))
                    if (hasDefaultDigest)
                    {
                        clog << "Syntax error: no digest requested for " << get<1>(files[0]) << "\n\n";
                        return false;
                    }
                    else
                        break;
        }
    }

    if (hasDefaultDigest)
    {
        if (explicitDigest.empty())
            explicitDigest.emplace_back(Digest::SHA256, string());

        for (auto &file: files)
            if (get<0>(file).empty())
                get<0>(file) = explicitDigest;
    }

    if (files.empty() && !digestSet.empty())
        files.emplace_back(tuple(digestSet, string()));

    return true;
}

static map<tuple<Digest, string>, unique_ptr<DigestEngine>>
    engineMap;

DigestEngine *buildDigestEngine(Digest digest, string const &passphrase, string const &fileName)
{
    auto it = engineMap.find(tuple(digest, passphrase));

    if (it != engineMap.end())
        return it->second.get();

    unique_ptr<DigestEngine> digestEngine;

    switch (digest)
    {
    case Digest::None:
        if (fileName.empty())
            clog << "Error: no digest specified\n";
        else
            clog << "Error: no digest specified for " << fileName << endl;

        throw runtime_error("No digest to compute for input data");

    case Digest::HMAC_MD5:
        digestEngine.reset(new HMACEngine<MD5Engine>(passphrase));
        break;

    case Digest::HMAC_SHA1:
        digestEngine.reset(new HMACEngine<SHA1Engine>(passphrase));
        break;

    case Digest::HMAC_SHA256:
        digestEngine.reset(new HMACEngine<SHA2Engine256>(passphrase));
        break;

    case Digest::MD4:
        digestEngine.reset(new MD4Engine());
        break;

    case Digest::MD5:
        digestEngine.reset(new MD5Engine());
        break;

    case Digest::PBKDF2_MD5:
        digestEngine.reset(new PBKDF2Engine<HMACEngine<MD5Engine>>(passphrase));
        break;

    case Digest::PBKDF2_SHA1:
        digestEngine.reset(new PBKDF2Engine<HMACEngine<SHA1Engine>>(passphrase));
        break;

    case Digest::PBKDF2_SHA256:
        digestEngine.reset(new PBKDF2Engine<HMACEngine<SHA2Engine256>>(passphrase));
        break;

    case Digest::SHA1:
        digestEngine.reset(new SHA1Engine());
        break;

    case Digest::SHA224:
        digestEngine.reset(new SHA2Engine224());
        break;

    case Digest::SHA256:
        digestEngine.reset(new SHA2Engine256());
        break;

    case Digest::SHA384:
        digestEngine.reset(new SHA2Engine384());
        break;

    case Digest::SHA512:
        digestEngine.reset(new SHA2Engine(SHA2Engine::SHA_512));
        break;

    case Digest::SHA512_224:
         digestEngine.reset(new SHA2Engine(SHA2Engine::SHA_512_224));
        break;

    case Digest::SHA512_256:
        digestEngine.reset(new SHA2Engine(SHA2Engine::SHA_512_256));
        break;

    default:
        if (fileName.empty())
            clog << "Error: no digest specified\n";
        else
            clog << "Error: no digest specified for " << fileName << endl;

        throw runtime_error("No digest to compute for input data");
    }

    return engineMap.emplace(tuple(digest, passphrase), digestEngine.release()).first->second.get();
}

char const *digestString(Digest digest)
{
    switch (digest)
    {
        case Digest::None:
            return ":              ";

        case Digest::HMAC_MD5:
            return "HMAC-MD5:      ";

        case Digest::HMAC_SHA1:
            return "HMAC-SHA1:     ";

        case Digest::HMAC_SHA256:
            return "HMAC_SHA256:   ";

        case Digest::MD4:
            return "MD4:           ";

        case Digest::MD5:
            return "MD5:           ";

        case Digest::PBKDF2_MD5:
            return "PBKDF2-MD5:    ";

        case Digest::PBKDF2_SHA1:
            return "PBKDF2-SHA1:   ";

        case Digest::PBKDF2_SHA256:
            return "PBKDF2-SHA256: ";

        case Digest::SHA1:
            return "SHA-1:         ";

        case Digest::SHA224:
            return "SHA-224:       ";

        case Digest::SHA256:
            return "SHA-256:       ";

        case Digest::SHA384:
            return "SHA-384:       ";

        case Digest::SHA512:
            return "SHA-512:       ";

        case Digest::SHA512_224:
            return "SHA512-224:    ";

        case Digest::SHA512_256:
            return "SHA512-256:    ";

        default:
            return":               ";
    }
}

map<Digest, vector<tuple<string, string>>>
    digestMap;

vector<Digest> digestOrderVect;

char digestBuffer[16u * 1024u];

void digestFile(DigestSet digestSet, string const &fileName, istream &inputFile)
{
    vector<DigestEngine *> digestEngines;

    for (auto &[digest, passphrase]: digestSet)
        digestEngines.emplace_back(buildDigestEngine(digest, passphrase, fileName));

    while (inputFile.good())
    {
        inputFile.read(digestBuffer, size(digestBuffer));

        for (auto digestStream : digestEngines)
            digestStream->update(digestBuffer, inputFile.gcount());
    }

    unsigned i = 0u;

    for (auto &[digest, passphrase]: digestSet)
    {
        auto &resultVector = digestMap[digest];

        if (resultVector.empty())
            digestOrderVect.push_back(digest);

        resultVector.emplace_back(DigestEngine::digestToHex(digestEngines[i++]->digest()), fileName);
    }
}

void digestFiles(DigestSet digestSet, string const &fileName)
{
    if (fileName.empty() || fileName == "-"s)
    {
#if defined(_WINDOWS) || defined(WIN32)
        HANDLEStreamBuf stdinInputBuf(GetStdHandle(STD_INPUT_HANDLE));
        auto rdbuf = cin.rdbuf();
        cin.rdbuf(&stdinInputBuf);
#endif

        digestFile(digestSet, string(), cin);

#if defined(_WINDOWS) || defined(WIN32)
        cin.rdbuf(rdbuf);
#endif
    }
    else
    {
        set<string> matchingFiles;

#if defined(_WINDOWS) || defined(WIN32)
        Glob::glob(fileName, matchingFiles, Glob::GLOB_FOLLOW_SYMLINKS | Glob::GLOB_CASELESS);

        if (matchingFiles.empty())
        {
            matchingFiles.insert(fileName);
            clog << "No such file: " << fileName << '\n';
            // return;
        }
#else
        matchingFiles.insert(fileName);
#endif

        for (auto const &fileName : matchingFiles)
            try
            {
                FileInputStream inputFile(fileName, inputFile.binary | inputFile.in);

                digestFile(digestSet, fileName, inputFile);
            }
            catch (exception const &exc)
            {
                clog << "Unable to hash conent of file " << fileName << ": " << exc.what() << '\n';
                continue;
            }
    }
}

void outputDigestStrings()
{
    for (Digest digest: digestOrderVect)
        for (auto const &[digestHexValue, fileName]: digestMap[digest])
        {
            cout << digestString(digest) << digestHexValue;

            if (!fileName.empty())
                cout << " *" << fileName;

            cout << endl;
        }
}

int main(int argc, char *argv[])
try
{
    vector<tuple<DigestSet, string>>
        files;

    if (!ParseCommandLine(files, argc, argv) || files.empty() && isStdInInteractive())
    {
        clog << "Sytax:\n";
        clog << '\t' << argv[0] << " --<digest> [passphrase] <input-files>...\n";
        clog << '\n';
        clog << "Compute specified digest (checksum) for given input data\n";
        clog << "Where --<digest> [passphrase] can be one of:\n";
        clog << '\n';
        clog << "      --hmac-md5 <passphrase>\n",
        clog << "      --hmac-sha1 <passphrase>\n",
        clog << "      --hmac-sha256 <passphrase>\n",
        clog << "      --md4\n",
        clog << "      --md5\n",
        clog << "      --pbkdf2-md5 <salt>\n",
        clog << "      --pbkdf2-sha1 <salt>\n",
        clog << "      --pbkdf2-sha256 <salt>\n",
        clog << "      --sha1\n",
        clog << "      --sha224\n",
        clog << "      --sha256\n",
        clog << "      --sha384\n",
        clog << "      --sha512\n",
        clog << "      --sha512-224\n",
        clog << "      --sha512-256\n",
        clog << '\n';
        clog << "The default checksum is SHA256\n";

        return EXIT_FAILURE;
    }

    if (files.empty())
        files.emplace_back(DigestSet { { Digest::SHA256, string() } }, string());

    for (auto const &file: files)
        digestFiles(get<0>(file), get<1>(file));

    outputDigestStrings();

    return EXIT_SUCCESS;
}
catch (exception const &exp)
{
    cerr << "Application error: " << exp.what() << "\n";
    cerr << "Termianted.";

    return EXIT_FAILURE;
}
catch (...)
{
    cerr << "Application error !\n";
    cerr << "Terminated!\n";

    return EXIT_FAILURE;
}
