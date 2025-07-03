package com.example.possible.util.listener

import com.example.possible.model.Letter

interface LettersListener {
    fun onClick(letter: Letter, position: Int)
}