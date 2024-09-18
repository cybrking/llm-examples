//@version=5
strategy("Simulated TICK Reversal Strategy", overlay=true, default_qty_type=strategy.percent_of_equity, default_qty_value=1, initial_capital=10000)

// Simulated TICK Index
advancing = request.security("NYSE:ADV", "1", close)
declining = request.security("NYSE:DEC", "1", close)
tick = advancing - declining

// TICK Levels
tick_short_entry = 1000
tick_long_entry = -1000

// Entry Conditions
short_condition = tick >= tick_short_entry
long_condition = tick <= tick_long_entry

// Take Profit and Stop Loss
take_profit_percent = 0.50 / 100
stop_loss_percent = 0.25 / 100

//