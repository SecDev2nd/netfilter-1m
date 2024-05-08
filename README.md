# nefilter-1m


Map을 사용한 경우    
저장 : 5sec ± 1sec    
탐색 : 1.8055e-05 s (0.000018055초?)  
  
Trie를 사용한 경우  
저장(배열) : 35sec ~ 7sec (첫 실행시 오래걸리고 갈수록 저장이 빨라짐, 왜지..)  
저장(std::unordered_map<char, TrieNode *>사용) : 25sec ± 1sec   
탐색 : 1.5102e-05 s (0.000015102초?)  

---
수정해야할 부분  
1. strstr함수 쓰지 말것  
2. map대신에 set을 쓰자, map과 탐색은 같은데 value가  없어서 메모리를 덜 차지한다.  
3. 두 자료구조의 메모리를 비교해보자.  

