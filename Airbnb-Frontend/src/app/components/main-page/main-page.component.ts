import { Component, OnInit } from '@angular/core';
import {AccommodationService} from "../../services/accommodation.service";
import { Location } from '../../models/location.model';
import {Router} from "@angular/router";
import { FormControl, FormGroup, Validators } from '@angular/forms';
import {MatSnackBar} from "@angular/material/snack-bar";
import { DateAdapter, MAT_DATE_FORMATS } from '@angular/material/core';

export const MY_DATE_FORMATS = {
  parse: {
    dateInput: 'LL',
  },
  display: {
    dateInput: 'DD/MM/YYYY',
    monthYearLabel: 'MMM YYYY',
    dateA11yLabel: 'LL',
    monthYearA11yLabel: 'MMMM YYYY',
  },
};


interface Accommodation {
  id?: string;
  name: string;
  description?: string;
  images: string;
  location: Location;
  benefits: string;
  minGuest: number;
  maxGuest: number;
  ownerId: string;
}

@Component({
  selector: 'app-main-page',
  templateUrl: './main-page.component.html',
  styleUrls: ['./main-page.component.css'],
  providers: [
    { provide: MAT_DATE_FORMATS, useValue: MY_DATE_FORMATS },
  ]
})
export class MainPageComponent implements OnInit {
  accommodations: Accommodation[] = [];
  locationFilter: string = '';
  minGuestsFilter: number | undefined;
  searchForm: FormGroup;

  startDateFilter = (date: Date | null): boolean => {
    return date !== null && date >= new Date();
  };

  endDateFilter = (date: Date | null): boolean => {
    return date !== null && date >= new Date();
  };


  constructor(private dateAdapter: DateAdapter<Date>,private accommodationService: AccommodationService, private router: Router, private _snackBar: MatSnackBar,) {
    this.searchForm = new FormGroup({
      location: new FormControl(''),
      minGuests: new FormControl(1),
      startDay: new FormControl('', [Validators.required]),
      endDay: new FormControl('', [Validators.required]),
    });
    this.dateAdapter.setLocale('en-GB');
  }

  ngOnInit(): void {
    this.initForm();
    this.getAccommodations();
  }

  initForm(): void {
    this.searchForm = new FormGroup({
      location: new FormControl(''),
      minGuests: new FormControl(1),
      startDay: new FormControl('', [Validators.required]),
      endDay: new FormControl('', [Validators.required]),
    });
  }

  getAccommodations(): void {
    this.accommodationService.getAllAccommodations().subscribe(
      (data) => {
        this.accommodations = data.sort((a: Accommodation, b: Accommodation) => {
          const idA = a.id ?? '';
          const idB = b.id ?? '';
          return idA > idB ? -1 : 1;
        });
        //console.log(data);
      },
      (error) => {
        console.error(error);
      }
    );
  }

  searchAccommodations(): void {

    const location = this.searchForm.get('location')?.value || '';
    const minGuests = this.searchForm.get('minGuests')?.value || 1;
    const startDay = this.searchForm.get('startDay')?.value;
    const endDay = this.searchForm.get('endDay')?.value;

    const startDateFormatted = startDay ? startDay.toISOString() : '';
    const endDateFormatted = endDay ? endDay.toISOString() : '';

    if (location || minGuests !== undefined || startDay || endDay) {
      this.accommodationService.searchAccommodations(location, minGuests, startDateFormatted, endDateFormatted).subscribe(
        (data: Accommodation[]) => {
          this.accommodations = data;
        },
        (error) => {
          console.error(error);
          if (error.status === 503 ) {
            this.openSnackBar("Reservation service is currently unavailable. Please try again later or try search without dates.", "");
          }
          else if (error.status === 502 ) {
            this.openSnackBar("Reservation service is currently unavailable. Please try again later or try search without dates.", "");
          }
        }
      );
    } else {
      this.getAccommodations();
      this.locationFilter = '';
      this.minGuestsFilter = undefined;
    }
  }

  openSnackBar(message: string, action: string) {
    this._snackBar.open(message, action,  {
      duration: 3500
    });
  }
}
