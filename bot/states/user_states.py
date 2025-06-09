from aiogram.fsm.context import FSMContext
from aiogram.filters.state import StateFilter
from aiogram.fsm.state import State, StatesGroup

class NameState(StatesGroup):
    waitingforName = State() 

class VirusTotal(StatesGroup):
    waitingforinput = State()   

class Shodan(StatesGroup):
    waitingforshodaninput = State()

class Censys(StatesGroup):
    waitingforcensysinput = State()

class Whois(StatesGroup):
    waitingforwhoisinput = State()

class UploadFile(StatesGroup):
    waitingforfile = State()

class FullScan(StatesGroup):
    waitingforfullscaninput = State()


