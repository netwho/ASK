-- This file documents the pattern for updating show_result_window calls
-- We need to change calls like:
--   show_result_window("DNS Registration Info: " .. domain, formatted)
-- To:
--   show_result_window_with_buttons("DNS Registration Info: " .. domain, formatted, "DNS RDAP", domain)

-- The pattern is: show_result_window_with_buttons(title, content, query_type, query_target)
