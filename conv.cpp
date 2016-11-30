#include <cstdio>
#include <cstdlib>
#include <string>
#include <iostream>
#include <sstream>
#include <map>

using namespace std;

int main()
{
    map<string, int> count;
    string line;
    int max = 0;
    while(getline(cin, line)) {
        int val = ++count[line];
        if(val > max) max = val;
    }

    cout << "digraph cfg {" << endl;
    for(auto it : count) {
        double width = (double)it.second * 10 / max;
        cout << "\t" << it.first << " [label=\"" << it.second << "\" penwidth=\"" << width << "\"];" << endl;
    }
    cout << "}" << endl;

    return 0;
}
