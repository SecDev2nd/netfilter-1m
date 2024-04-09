#include <cstring>
#include <string>

#define CHAR_LENGTH 27

class TrieNode
{
private:
    TrieNode *child[CHAR_LENGTH] = {NULL};
    bool finish = false;

    int checkChr(const char ch)
    {
        int current;
        if (ch >= 'a' && ch <= 'z')
        {
            current = ch - 'a';
        }
        else if (ch >= '0' && ch <= '9')
        {
            current = ch - '0'; // 알파벳 다음부터 인덱스 계산
        }
        else
        {
            current = 26; // '.'의 인덱스
        }
        return current;
    }

public:
    TrieNode() {}

    ~TrieNode()
    {
        for (int i = 0; i < CHAR_LENGTH; i++)
        {
            if (child[i])
            {
                delete child[i];
                child[i] = nullptr;
            }
        }
    }

    friend class Trie;
};

class Trie
{
private:
    TrieNode *root;

public:
    // Constructor
    Trie()
    {
        this->root = new TrieNode();
    }

    // Destructor
    ~Trie()
    {
        delete root;
    }

    void insert(const std::string &str)
    {
        TrieNode *current = this->root;

        for (const char ch : str)
        {
            int next = current->checkChr(ch);
            if (current->child[next] == NULL)
            {
                current->child[next] = new TrieNode();
                
            }
            current = current->child[next];
            
        }

        current->finish = true;
    }

    bool find(const std::string &str)
    {
        TrieNode *current = this->root;

        for (const char ch : str)
        {
            int next = current->checkChr(ch);
            if (current->child[next] == NULL)
            {
                return 0;
            }
            current = current->child[next];
        }

        return current->finish;
    }
};
