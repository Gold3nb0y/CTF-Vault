#include <iostream>
#include <cstdint>
#include <unordered_map>

using namespace std;

int main(void) {
   unordered_map<unsigned int, uint64_t> um = {
            {1, 0x41},
            {0x1000, 0x41},
            {0x1FFF, 0x41},
            {0x2FFE, 0x41},
            {0x3FFD, 0x41},
            {0x4FFC, 0x41},
            {0x5FFB, 0x41},
            };

   for (auto it = um.begin(); it != um.end(); ++it) {
      cout << "Element " << "[" << it->first  << " : "
          << it->second << "] " << "is in " 
          << um.bucket(it->first) << " bucket." << endl; 
   }

   return 0;
}
