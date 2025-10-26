return {
  {
    "Fildo7525/pretty_hover",
    event = "LspAttach",
    opts = {},
    -- completion = {
    --   documentation = {
    --     draw = function(opts)
    --       if opts.item and opts.item.documentation and opts.item.documentation.value then
    --         local out = require("pretty_hover.parser").parse(opts.item.documentation.value)
    --         opts.item.documentation.value = out:string()
    --       end
    --
    --       opts.default_implementation(opts)
    --     end,
    --   },
    -- },
    config = function()
      vim.keymap.set("n", "<M-s>", function()
        require("pretty_hover").hover()
      end, { desc = "Toggle pretty hover" })

      vim.keymap.set("n", "<M-c>", function()
        require("pretty_hover").close()
      end, { desc = "Toggle pretty hover close" })
    end,
  },
}
