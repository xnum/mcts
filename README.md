
## Installation

最新版的angr似乎有修改過本程式使用的相關接口

因此最新版的是否能在無修改程式碼下直接執行還未確定

先安裝angr的dev版本

且設定好virtualenv相關配置

將angr/angr/exploration_techniques/dfs.py替換為本程式的dfs.py

如有缺少MCTSTree的dependency，請在virtualenv的path中自行加入

## Usage

可以手動執行scripts/下的檔案來分別測試單一程式

`$ python scripts/ls.py MCTS 3000`

MCTS可換為DFS或BFS

3000可自定義數字 為限制執行資源的參數

也可以透過runall.sh 執行所有scripts/下的實驗

runall因為會把輸出導向到檔案 會遇到緩衝區不夠的情形

需要再安裝unbuffer以解決問題

time.sh是整理某資料夾下的運行時間

convert.sh要先編譯conv.cpp

可以輔助把執行過程畫成圖 但要安裝dot

lib/MCTSTree.py 是我自己實作的MCTS樹結構

可能有些corner case會出Bug...
