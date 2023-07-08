" set softtabstop
set smarttab
set mouse=a
set number
set autoindent
set shiftwidth=4    " Set shift width to 4 spaces.
set tabstop=4       " Set tab width to 4 columns.
set relativenumber  " Set relative numbering with absolute line number for cursor line
set expandtab       " Use space characters instead of tabs.
set showmode        " Show the mode you are on the last line.
set showmatch       " Show matching words during a search.
set hlsearch        " Use highlighting when doing a search.
set history=1000    " Set the commands to save in history default number is 20.
syntax on           " Turn syntax highlighting on.

" copy (write) highlighted text to .vimbuffer
vmap <C-c> y:new ~/.vimbuffer<CR>VGp:x<CR> \| :!cat ~/.vimbuffer \| clip.exe <CR><CR>    

" paste from buffer
vmap <C-v> :r ~/.vimbuffer<CR> 
