package handler

import (
    di "secure-file-hub/internal/infrastructure/di"
)

var appContainer *di.Container

func SetContainer(c *di.Container) {
    appContainer = c
}

