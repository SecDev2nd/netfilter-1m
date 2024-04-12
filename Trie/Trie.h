#include <cstring>
#include <string>
#include <unordered_map>
#include <iostream>
#define CHAR_LENGTH 27

class TrieNode
{
public:
    std::unordered_map<char, TrieNode *> children;
    bool isFinish;

    TrieNode() : isFinish(false) {}

    TrieNode *getChild(char ch)
    {
        if (children.find(ch) != children.end())
        {
            return children[ch];
        }
        return nullptr;
    }

    TrieNode *addChild(char ch)
    {
        TrieNode *node = new TrieNode();
        children[ch] = node;
        return node;
    }
};

class Trie
{
private:
    TrieNode *root;

public:
    Trie()
    {
        root = new TrieNode();
    }

    void insert(const std::string &str)
    {
        TrieNode *current = this->root;

        for (const char ch : str)
        {
            if (!current->getChild(ch))
            {
                current->addChild(ch);
            }
            current = current->getChild(ch);
        }

        current->isFinish = true;
    }

    bool find(const std::string &str)
    {
        TrieNode *current = this->root;

        for (const char ch : str)
        {
            current = current->getChild(ch);
            if (!current)
            {
                return false;
            }
        }

        return current->isFinish;
    }

    void printAll()
    {
        std::string str;
        printAllHelper(this->root, str);
    }

    void printAllHelper(TrieNode *node, std::string str)
    {
        if (node->isFinish)
        {
            std::cout << str << std::endl;
        }

        for (auto it = node->children.begin(); it != node->children.end(); ++it)
        {
            printAllHelper(it->second, str + it->first);
        }
    }
};
