return {
  "nvim-java/nvim-java",
  config = false,
  dependencies = {
    {
      "neovim/nvim-lspconfig",
      opts = {
        servers = {
          jdtls = {
            settings = {
              java = {
                configuration = {
                  runtimes = {
                    {
                      name = "SDKCurrent",
                      path = "$JAVA_HOME",
                      default = true,
                    },
                  },
                },
              },
            },
          },
        },
      },

      setup = {
        jdtls = function()
          require("java").setup({
            jdk = {
              auto_install = false,
            },
          })
        end,
      },
    },
  },
}
