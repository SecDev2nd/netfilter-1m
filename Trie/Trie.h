
#include <cstring>

#define CHAR_LENGTH 27

struct Trie
{
    bool finish;
    Trie *next[CHAR_LENGTH];

    // Constructor
    Trie() : finish(false)
    {
        memset(next, 0, sizeof(next));
    }

    // Destructor
    ~Trie()
    {
        for (int i = 0; i < CHAR_LENGTH; i++)
        {
            if (next[i])
            {
                delete next[i];
            }
        }
    }

    void insert(const char *key)
    {
        if (*key == '\0')
        {
            finish = true; // End of the word
        }
        else
        {
            int current = *key - 'a'; // Convert to index
            if (next[current] == NULL)
            {
                next[current] = new Trie();
            }
            next[current]->insert(key + 1);
        }
    }

    Trie *find(const char *key)
    {
        if (*key == '\0')
        {
            return this; // End of the word
        }
        int current = *key - 'a';
        if (next[current] == NULL)
        {
            return NULL;
        }
        return next[current]->find(key + 1);
    }
};
