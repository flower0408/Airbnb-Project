import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Accommodation } from 'src/app/models/accommodation.model';
import { User } from 'src/app/models/user.model';
import { AccommodationService } from 'src/app/services/accommodation.service';
import { UserService } from 'src/app/services/user.service';
import { UpperLetterValidator } from 'src/app/services/customValidators';
import { MaxGuestValidator } from 'src/app/services/customValidators';
import {MatSnackBar} from "@angular/material/snack-bar";
import {Router} from "@angular/router";
import {HttpErrorResponse} from "@angular/common/http";
import { ViewChild } from '@angular/core';
import { Appointment } from 'src/app/models/appointment.model';
import { AppointmentService } from 'src/app/services/appointment.service';

declare var $: any; // Declare jQuery

@Component({
  selector: 'app-create-accommodation',
  templateUrl: './create-accommodation.component.html',
  styleUrls: ['./create-accommodation.component.css']
})
export class CreateAccommodationComponent implements OnInit{

  accommodationForm!: FormGroup;
  responseId: any;

  @ViewChild('datapicker') dateInput!: ElementRef;

  ngAfterViewInit() {
    $(this.dateInput.nativeElement).daterangepicker({
      locale: {
        format: 'YYYY/MM/DD',
      },
      minDate: new Date(),
    });
  }

  constructor(private fb: FormBuilder,private accommodationService: AccommodationService,private userService:UserService, private _snackBar: MatSnackBar, private router: Router,private appointmentService:AppointmentService) {
  }

  get f(): { [key: string]: AbstractControl } {
    return this.accommodationForm.controls;
  }

  ngOnInit(): void {

   this.accommodationForm = this.fb.group({
     name: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(35), Validators.pattern(/^[a-zA-Z0-9\s,'-]{3,35}$/)]],
     description: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(200), Validators.pattern(/^[a-zA-Z0-9\s,'-]{3,200}$/)]],
     images: ['', [Validators.required,Validators.pattern(/^[a-zA-Z0-9\s,'-]{3,200}$/)]],
     benefits: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(100), Validators.pattern(/^[a-zA-Z0-9\s,'-]{3,100}$/)]],
     Minguest: ['', [Validators.required, Validators.min(1)]],
     Maxguest: ['', [Validators.required,Validators.min(1), MaxGuestValidator(/*this.accommodationForm.get('Minguest')*/)]],
     country: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(35),UpperLetterValidator(), Validators.pattern(/^[A-Z][a-zA-Z\s-]{2,35}$/)]],
     city: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(35),UpperLetterValidator(), Validators.pattern(/^[A-Z][a-zA-Z\s-]{2,35}$/)]],
     street: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(35),UpperLetterValidator(), Validators.pattern(/^[A-Z][a-zA-Z0-9\s,'-]{2,35}$/)]],
     number: ['', [Validators.required, Validators.min(1)]],
     datepicker: [''],
     price: ['', [Validators.required]]
   });
  }

  submitted = false;

  onSubmit(){
    this.submitted = true;

    if (this.accommodationForm.valid) {

      const formValues = this.accommodationForm.value;

      const newAccommodation: Accommodation = {
        name: formValues.name,
        description: formValues.description,
        images: formValues.images,
        location: {
          country: formValues.country,
          city: formValues.city,
          street: formValues.street,
          number: formValues.number
        },
        benefits: formValues.benefits,
        minGuest: formValues.Minguest,
        maxGuest: formValues.Maxguest,
        ownerId: '',
      };



      this.accommodationService.createAccommodation(newAccommodation).subscribe(
        () => {

          let elements = document.getElementsByClassName("drp-selected");
          let dateRange:any;
          for (var i = 0; i < elements.length; i++) {
            dateRange = elements[i].textContent;
            console.log(dateRange);
          }

          let [start, end] = dateRange!.split(" - ");

          let datesInRange: Date[] = getDatesInRange(start, end);
          console.log(datesInRange);

          const newAppointment: Appointment = {
            id:"",
            available: datesInRange,
            accommodationId: "",
            pricePerGuest: 0,
            pricePerAccommodation: 0
          };

          let selectedRadio = getSelectedRadio();
          console.log(selectedRadio);

          if(selectedRadio === 'Guest price'){
            newAppointment.pricePerGuest = formValues.price;
          }else{
            newAppointment.pricePerAccommodation = formValues.price;
          }

          this.appointmentService.createAppointment(newAppointment).subscribe(
            () => {

              this.openSnackBar("Accommodation created successfully!", "")
              console.log('Appointment created successfully!');
              this.router.navigate(['/Main-Page'])

            },
            (error) => {
              this.openSnackBar("Error creating accommodation!", "")
              console.error('Error creating appointment:', error);
            }
          );

        },
        (error) => {
          console.error('Error creating accommodation:', error);
        }
      );

          this.openSnackBar("Accommodation created successfully!", "");
          console.log('Accommodation created successfully!');
          this.router.navigate(['/Main-Page']);
        },
        (error) => {
          console.error('Error creating accommodation:', error);

          if (error instanceof HttpErrorResponse) {
            if (error.status === 503) {
              this.openSnackBar("User service is currently unavailable. Please try again later.", "");
            }
            else if (error.status === 502) {
              this.openSnackBar("User service is currently unavailable. Please try again later.", "");
            }
            else {
              this.openSnackBar(`Error creating accommodation: ${error.message}`, "");
            }
          } else {
            console.error('Error creating accommodation:', error);
           // this.openSnackBar(`Unexpected error: ${error}`, "");
          }
        }
      );

    }
  }

  openSnackBar(message: string, action: string) {
    this._snackBar.open(message, action,  {
      duration: 3500
    });
  }

}

function getDatesInRange(startDate: string, endDate: string): Date[] {
  const dateList: Date[] = [];
  let currentDate = new Date(startDate);

  while (currentDate <= new Date(endDate)) {
    currentDate.setDate(currentDate.getDate() + 1);
    dateList.push(new Date(currentDate));
  }

  return dateList;
}

function getSelectedRadio() {
  const radioButtons = document.getElementsByName('flexRadioDefault');
  const radioArray = Array.from(radioButtons);

  for (const radioButton of radioArray) {
    if ((radioButton as HTMLInputElement).checked) {
      return (radioButton as HTMLInputElement).value;
    }
  }

  return null;
}


