// scriptparser.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <regex>
#include "Shlwapi.h"
#include <boost/regex.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <openssl/md5.h>
#include <algorithm>

namespace po = boost::program_options;
namespace fs = boost::filesystem;

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib")

std::wstring removeExtension(std::wstring const& filepath);
std::wstring getDirPath(std::wstring const& filepath);
std::wstring getFilename(std::wstring const& filepath);
std::wstring absoluteFilePath(const TCHAR *path);
std::wstring replaceAll(std::wstring str, const std::wstring& from, const std::wstring& to);
bool isReserved(std::wstring s);
std::wstring tr(const boost::wsmatch &m);
std::wstring convertScriptToRegexp(std::wstring script);
bool extractScripts(std::wstring filepath);
std::wstring getMD5(std::wstring path);

class YaraRule 
{

	std::wstring name;
	std::list <std::wstring> signatures;
	std::wstring condition;
	std::wstring author;
	std::wstring date;
	std::wstring description;
	std::wstring verdict;
	std::wstring md5;

public:
	YaraRule()
	{
		this->name = L"myrule"; 
		this->signatures = std::list <std::wstring>();
		this->condition = L"any of them";
		this->author = L"Andrey Vishnevsky (andrey.s.vishnevsky@gmail.com)";
		this->date = boost::gregorian::to_iso_extended_wstring(boost::gregorian::day_clock::local_day());
		this->description = L"malware";
		this->verdict = L"true";
	}

	YaraRule(std::wstring const& name, std::list <std::wstring> const& signatures, std::wstring const& condition, std::wstring const& md5)
	{
		this->name = name;
		this->signatures = signatures;
		this->condition = condition;
		this->author = L"Andrey Artyushkin (andrey.s.vishnevsky@gmail.com)";
		this->date = boost::gregorian::to_iso_extended_wstring(boost::gregorian::day_clock::local_day());
		this->description = L"malware";
		this->verdict = L"true";
		this->md5 = md5;
	}

	std::wstring getName()
	{
		return this->name;
	}

	std::wstring getText()
	{
		std::wstring text;
		text += L"rule " + this->name + L"\n";
		text += L"{\n";
		text += L"\tmeta:\n";
		text += L"\t\tmd5 = \"" + this->md5 + L"\"\n";
		text += L"\t\tauthor = \"" + this->author + L"\"\n";
		text += L"\t\tdate = \"" + this->date + L"\"\n";
		text += L"\t\tdescription = \"" + this->description + L"\"\n";
		text += L"\t\tverdict = \"" + this->verdict + L"\"\n";
		text += L"\n";
		text += L"\tstrings:\n";

		int i = 0;
		for (auto x : this->signatures) {
			text += L"\t\t$s" + std::to_wstring(i) + L" = /" + x + L"/ nocase\n\n";
			i++; 
		}
		
		text += L"\tcondition:\n";
		text += L"\t\t" + this->condition + L"\n";
		text += L"}\n";
		return text;
	}

	void show() 
	{
		std::wcout << this->getText();
	}

	void saveToFile(std::wstring const& filepath)
	{
		std::wofstream fout;
		fout.open(filepath);
		fout << this->getText();
		fout.close();
	}
};

void createRuleForFile(std::wstring filepath, std::wstring rulename, int id);

int _tmain(int argc, _TCHAR* argv[])
{
	// Declare the supported options.
	po::options_description desc("Allowed options");
	desc.add_options()
		("help", "produce help message")
		("file", po::wvalue<std::wstring>(), "path to analysing file")
		("path", po::wvalue<std::wstring>(), "path to folder with scripts for making rules")
		("rule", po::wvalue<std::wstring>(), "verdict for Yara-rule")
		;

	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);
	
	if (vm.count("file") && !vm.count("path") && !vm.count("rule")) {
		std::wcout << L"[*] Filepath is set to "
			<< vm["file"].as<std::wstring>() << L".\n";

		std::wstring filepath = vm["file"].as<std::wstring>();
		std::wcout << filepath << std::endl;

		extractScripts(filepath);
	}	
	else if (vm.count("file") && !vm.count("path") && vm.count("rule")) {	

		std::wstring filepath = vm["file"].as<std::wstring>();
		std::wstring rulename = vm["rule"].as<std::wstring>();
		createRuleForFile(filepath, rulename, 0);
		return 0;
	}
	else if (!vm.count("file") && vm.count("path") && vm.count("rule")) {
		std::wstring dirpath = vm["path"].as<std::wstring>();
		std::wstring rulename = vm["rule"].as<std::wstring>();

		try
		{
			if (fs::exists(dirpath))    
			{
				if (fs::is_directory(dirpath))      
				{
					fs::directory_iterator end_itr;
					int id = 0;
					for (fs::directory_iterator itr(dirpath); itr != end_itr; ++itr)
					{						
						if (is_regular_file(itr->path())) {							
							std::wstring current_file = itr->path().wstring();							
							
							// Process current file
							createRuleForFile(current_file, rulename, id);
							id++;

						}
					}

				}
				else
					std::wcout << dirpath << " exists, but is not a directory\n";
			}
			else
				std::wcout << dirpath << " does not exist\n";
		}

		catch (const fs::filesystem_error& ex)
		{
			std::cout << ex.what() << '\n';
		}



	}

	else {
		std::cout << desc << "\n";
		return 1;
	}

	return 0;
}

void createRuleForFile(std::wstring filepath, std::wstring rulename, int id)
{
	std::wcout << filepath << " " << rulename << std::endl;

	// Convert script to regular expression		
	std::wcout << L"[!] Make sure that \"" << getFilename(filepath) << "\" is a script, not entire HTML page." << std::endl;
	std::wifstream wfin;
	wfin.open(filepath);
	std::wstring line;
	line.assign(std::istreambuf_iterator<wchar_t>(wfin), std::istreambuf_iterator<wchar_t>());
	std::list <std::wstring> signatures;
	std::list <std::wstring> regexs;

	if (line.size() > 320) {
		std::wstring line_begin = std::wstring(line, 0, 320);
		std::wstring line_end = std::wstring(line, line.size() - 320, 320);
		signatures.push_back(line_begin);
		signatures.push_back(line_end);
	}
	else
		signatures.push_back(line);

	for (auto x : signatures) {
		std::wstring generated_regex = convertScriptToRegexp(x);
		regexs.push_back(generated_regex);
	}

	fs::create_directory(L"_rules");
	YaraRule ya(rulename + L"_" + std::to_wstring(id), regexs, L"all of them", getMD5(filepath));	
	ya.saveToFile(L"_rules\\" + removeExtension(getFilename(filepath)) + L"_" + std::to_wstring(id) + L".yar");
	wfin.close();
}

std::wstring removeExtension(std::wstring const& filepath)
{
	std::wstring::const_reverse_iterator pivot = std::find(filepath.rbegin(), filepath.rend(), '.');
	return pivot == filepath.rend() ? filepath : std::wstring(filepath.begin(), pivot.base() - 1);
}

std::wstring getDirPath(std::wstring const& filepath)
{	
	std::wstring::const_reverse_iterator pivot = std::find(filepath.rbegin(), filepath.rend(), '\\');
	return pivot == filepath.rend() ? L"" : std::wstring(filepath.begin(), pivot.base());
}

std::wstring getFilename(std::wstring const& filepath)
{
	std::wstring::const_reverse_iterator pivot = std::find(filepath.rbegin(), filepath.rend(), '\\');
	return pivot == filepath.rend() ? filepath : std::wstring(pivot.base(), filepath.end());
}

std::wstring absoluteFilePath(const TCHAR *path)
{
	static const std::size_t BufferSize = 300;
	TCHAR absolute_path[BufferSize];

	GetFullPathName(path, BufferSize, absolute_path, 0);

	return std::wstring(absolute_path);
}

std::wstring replaceAll(std::wstring str, const std::wstring& from, const std::wstring& to) 
{
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
	}
	return str;
}

bool isReserved(std::wstring s)
{
	std::list<std::wstring> Reserved = {
		L"script", L"function", L"type", L"text", L"javascript", L"return", L"parseint", L"var", L"for", L"length",
		L"string", L"fromcharcode", L"substr", L"document", L"write", L"src", L"setattribute", L"createElement", L"body",
		L"appendchild", L"catch", L"replace", L"language", L"array", L"indexof", L"charat", L"eval", L"onload", L"try",
		L"this", L"if", L"new", L"createobject", L"wshshell", L"shell", L"expandenvironmentstrings", L"activexobject",
		L"cmd", L"run", L"wscript", L"temp", L"setlocal", L"enabledelayedexpansion", L"tokens", L"query", L"exe", L"hklm",
		L"software", L"microsoft", L"windows", L"nt", L"currentversion", L"do", L"set", L"not", L"goto", L"vbs",
		L"errorlevel", L"geq", L"del", L"js", L"docume", L"echo", L"setattribute"
	};

	std::transform(s.begin(), s.end(), s.begin(), ::tolower);
	std::list<std::wstring>::iterator it;
	for (it = Reserved.begin(); it != Reserved.end(); it++)
		if (s == *it)
			return true;

	return false;
}

std::wstring tr(const boost::wsmatch &m)
{
	return isReserved(m[0].str()) ? m[0].str() : L"\\w+";
}

std::wstring convertScriptToRegexp(std::wstring script)
{
	script = replaceAll(script, L"\\", L"\\\\");
	script = replaceAll(script, L"(", L"\\(");
	script = replaceAll(script, L")", L"\\)");
	script = replaceAll(script, L"[", L"\\[");
	script = replaceAll(script, L"]", L"\\]");
	script = replaceAll(script, L".", L"\\.");
	script = replaceAll(script, L"+", L"\\+");
	script = replaceAll(script, L"/", L"\\/");
	script = replaceAll(script, L"?", L"\\?");
	script = replaceAll(script, L"*", L"\\*");
	script = replaceAll(script, L"^", L"\\^");
	script = replaceAll(script, L"$", L"\\$");
	script = replaceAll(script, L"|", L"\\|");
	script = replaceAll(script, L"\n", L" ");

	script = boost::regex_replace(script, boost::wregex(L"\\w+"), tr);
	script = boost::regex_replace(script, boost::wregex(L"\\s+"), L"\\\\s+");
	//std::wcout << script << std::endl;

	return script;
}

bool extractScripts(std::wstring filepath)
{
	try
	{
		std::wstring dirpath = getDirPath(filepath);
		std::wstring basename = getFilename(filepath);
		//std::wcout << L"[DEBUG]: dirpath  = \"" << dirpath << L"\"" << std::endl;
		//std::wcout << L"[DEBUG]: basename = \"" << basename << L"\"" << std::endl;
		//std::wcout << L"[DEBUG]: removeExtension(basename) = \"" << removeExtension(basename) << L"\"" << std::endl;

		//Create folder for extracted scripts
		fs::create_directory(L"_" + basename + L"_");

		std::wifstream fin(filepath);
		std::wstring line;
		line.assign(std::istreambuf_iterator<wchar_t>(fin), std::istreambuf_iterator<wchar_t>());

		std::wsmatch m;
		std::wregex pattern(L"<script[^]*?</script>", std::regex_constants::icase);

		std::wstring scriptpath;
		std::wofstream fout;
		std::wstring generated_regex;

		int i = 0;
		while (std::regex_search(line, m, pattern)) {
			for (auto x : m)
			{
				generated_regex = convertScriptToRegexp(x);

				fout.open(dirpath + L"_" + basename + L"_\\" + removeExtension(basename) + std::to_wstring(i) + L".js_");
				fout << x;
				fout.close();	
				
			}
			line = m.suffix().str();
			i++;
		}
	}
	catch (int e)
	{
		std::wcout << "Caught exception number:  " << e << std::endl;
		return false;
	}
	return true;
}

std::wstring getMD5(std::wstring path)
{
	TCHAR result[33];
	unsigned char c[MD5_DIGEST_LENGTH];
	int i;
	FILE* inFile;
	_tfopen_s(&inFile, path.c_str(), TEXT("rb"));
	MD5_CTX mdContext;
	size_t bytes;
	unsigned char data[1024];
	char temp[3];

	if (inFile == NULL) {
		printf("%s can't be  opened.\n", path.c_str());
		return 0;
	}

	MD5_Init(&mdContext);
	while ((bytes = fread(data, 1, 1024, inFile)) != 0)
		MD5_Update(&mdContext, data, bytes);
	MD5_Final(c, &mdContext);
	for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
		sprintf_s(temp, "%02x", c[i]);
		result[2 * i] = temp[0];
		result[2 * i + 1] = temp[1];
	}
	result[32] = '\0';	

	fclose(inFile);

	return std::wstring(result);

}