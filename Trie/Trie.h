
#include <cstring>

#define CHAR_LENGTH 27

using namespace std;

struct Trie
{
    bool finish;
    Trie *node[CHAR_LENGTH];

    // Constructor
    Trie() : finish(false)
    {
        memset(node, 0, sizeof(node));
    }

    // Destructor
    ~Trie()
    {
        for (int i = 0; i < CHAR_LENGTH; i++)
        {
            if (node[i])
            {
                delete node[i];    // 노드가 널 포인터인지 확인 후 삭제
                node[i] = nullptr; // 삭제된 노드를 널로 설정하여 이중 삭제를 방지
            }
        }
    }

    int checkChr(const char *key)
    {
        int current;
        if (*key >= 'a' && *key <= 'z')
        {
            current = *key - 'a';
        }
        else if (*key >= '0' && *key <= '9')
        {
            current = *key - '0'; // 알파벳 다음부터 인덱스 계산
        }
        else
        {
            current = 26; // '.'의 인덱스
        }
        return current;
    }

    void insert(string &key, int index)
    {

        if (index == key.length() - 1)
        {
            finish = true;
        }
        else
        {
            int next = checkChr(&key[index]);
            if (node[next] == NULL)
            {
                node[next] = new Trie();
            }
            node[next]->insert(key, index + 1);
        }
    }

    bool find(const char *key)
    {
        if (*key == '\0')
        {
            return finish;
        }
        int current = checkChr(key);
        if (node[current] == NULL)
        {
            return NULL;
        }
        return node[current]->find(key + 1);
    }
};
