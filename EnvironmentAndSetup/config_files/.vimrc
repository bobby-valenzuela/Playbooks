" Set shift width to 4 spaces.
set shiftwidth=4

" Set tab width to 4 columns.
set tabstop=4

" Use space characters instead of tabs.
set expandtab

" Set relative numbering with absolute line number for cursor line
set number
set relativenumber

" Turn syntax highlighting on.
syntax on

" Show the mode you are on the last line.
set showmode

" Show matching words during a search.
set showmatch

" Use highlighting when doing a search.
set hlsearch

" Set the commands to save in history default number is 20.
set history=1000

" [WSL] copy (write) highlighted text to .vimbuffer with Ctrl+C
vmap <C-c> y:new ~/.vimbuffer<CR>VGp:x<CR> \| :!cat ~/.vimbuffer \| clip.exe <CR><CR>
" [WSL] paste from buffer with Ctrl+V
map <C-v> :r ~/.vimbuffer<CR>
