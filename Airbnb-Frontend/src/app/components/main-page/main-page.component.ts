import { Component, OnInit } from '@angular/core';
import {AccommodationService} from "../../services/accommodation.service";
import { UserService } from '../../services/user.service';
import { Location } from '../../models/location.model';
import {Router} from "@angular/router";
import { FormControl, FormGroup, Validators } from '@angular/forms';
import {MatSnackBar} from "@angular/material/snack-bar";
import { DateAdapter, MAT_DATE_FORMATS } from '@angular/material/core';

/*export const MY_DATE_FORMATS = {
  parse: {
    dateInput: 'LL',
  },
  display: {
    dateInput: 'DD/MM/YYYY',
    monthYearLabel: 'MMM YYYY',
    dateA11yLabel: 'LL',
    monthYearA11yLabel: 'MMMM YYYY',
  },
};*/


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
  highlighted?: boolean;
}

export class User {
    id: string = "";
    firstName: string = "";
    lastName: string = "";
    gender: string = "";
    age: number = 0;
    residence: string = "";
    username: string = "";
    password: string = "";
    email: string = "";
    userType: string = "";
    highlighted: boolean = false;

    User(id:string,firstName: string, lastName: string, gender: string, age: number, residence: string, username: string, password: string, email: string, userType: string, highlighted: boolean) {
        this.id = id;
        this.firstName = firstName;
        this.lastName = lastName;
        this.gender = gender;
        this.age = age;
        this.residence = residence;
        this.username = username;
        this.password = password;
        this.email = email;
        this.userType = userType;
        this.highlighted = highlighted;
    }
}

@Component({
  selector: 'app-main-page',
  templateUrl: './main-page.component.html',
  styleUrls: ['./main-page.component.css'],
 /* providers: [
    { provide: MAT_DATE_FORMATS, useValue: MY_DATE_FORMATS },
  ]*/
})
export class MainPageComponent implements OnInit {
  accommodations: Accommodation[] = [];
  locationFilter: string = '';
  minGuestsFilter: number | undefined;
  searchForm: FormGroup;
  filterParams = {
      desiredBenefits: [] as string[],
      minPrice: '',
      maxPrice: '',
      highlightedHost: false,
    };
  newBenefit: string = '';

  startDateFilter = (date: Date | null): boolean => {
    if (!date) {
      return false;
    }

    // Get the current date without the time component
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Compare only the date part
    return date >= today;
  };

  endDateFilter = (date: Date | null): boolean => {
    if (!date) {
      return false;
    }

    // Get the current date without the time component
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Compare only the date part
    return date >= today;
  };



  constructor(/*private dateAdapter: DateAdapter<Date>,*/private accommodationService: AccommodationService, private router: Router, private _snackBar: MatSnackBar, private userService: UserService) {
    this.searchForm = new FormGroup({
      location: new FormControl(''),
      minGuests: new FormControl(1),
      startDay: new FormControl('', [Validators.required]),
      endDay: new FormControl('', [Validators.required]),
    });
    //this.dateAdapter.setLocale('en-GB');
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
        this.accommodations = data;

        this.accommodations.forEach((accommodation) => {
          this.userService.getUserById(accommodation.ownerId).subscribe(
            (host: User) => {
              accommodation.highlighted = host.highlighted;

              this.accommodations.sort((a, b) => {
                const highlightedA = a?.highlighted || false;
                const highlightedB = b?.highlighted || false;

                if (highlightedA === highlightedB) {
                  const idA = a.id ?? '';
                  const idB = b.id ?? '';
                  return idA > idB ? -1 : 1;
                } else {
                  return highlightedB ? 1 : -1;
                }
              });
            },
            (error) => {
              console.error('Error fetching host:', error);
            }
          );
        });
      },
      (error) => {
        console.error(error);
      }
    );
  }
  addBenefit() {
    if (this.newBenefit.trim() !== '') {
      this.filterParams.desiredBenefits.push(this.newBenefit.trim());
      this.newBenefit = '';
    }
  }

  removeBenefit(benefit: string) {
    const index = this.filterParams.desiredBenefits.indexOf(benefit);
    if (index !== -1) {
      this.filterParams.desiredBenefits.splice(index, 1);
    }
  }

  filterAccommodations() {
    if (this.isHighlightedHostChecked()) {
        this.filterParams.highlightedHost = true;
    }

    if (this.filterParamsIsEmpty()) {
       this.getAccommodations();
    } else {
      console.log(this.filterParams);
      this.accommodationService.filterAccommodations(this.filterParams).subscribe(
        (data) => {
          this.accommodations = data;

          if (this.accommodations && this.accommodations.length > 0) {
            this.accommodations.forEach((accommodation) => {
              this.userService.getUserById(accommodation.ownerId).subscribe(
                (host: User) => {
                  accommodation.highlighted = host.highlighted;

                  this.accommodations.sort((a, b) => {
                    const highlightedA = a?.highlighted || false;
                    const highlightedB = b?.highlighted || false;

                    if (highlightedA === highlightedB) {
                      const idA = a.id ?? '';
                      const idB = b.id ?? '';
                      return idA > idB ? -1 : 1;
                    } else {
                      return highlightedB ? 1 : -1;
                    }
                  });
                },
                (error) => {
                  console.error('Error fetching host:', error);
                }
              );
            });
          }
        },
        (error) => {
          console.error('Error fetching accommodations:', error);
        }
      );
    }
  }

  isHighlightedHostChecked() {
    const highlightedHostCheckbox = document.getElementById('highlightedHost') as HTMLInputElement;

    return highlightedHostCheckbox.checked;
  }

  filterParamsIsEmpty(): boolean {
    return (
      !this.filterParams.desiredBenefits.length &&
      !this.filterParams.minPrice &&
      !this.filterParams.maxPrice &&
      !this.filterParams.highlightedHost
    );
  }

  searchAccommodations(): void {

    const location = this.searchForm.get('location')?.value || '';
    const minGuests = this.searchForm.get('minGuests')?.value || 1;
    const startDay = this.searchForm.get('startDay')?.value;
    const endDay = this.searchForm.get('endDay')?.value;

    const startDate = startDay ? new Date(startDay.getTime() + 24 * 60 * 60 * 1000) : null;

    const endDate = endDay ? new Date(endDay.getTime() + 24 * 60 * 60 * 1000) : null;

    const startDateFormatted = startDate ? startDate.toISOString() : '';
    const endDateFormatted = endDate ? endDate.toISOString() : '';

    console.log('Formatted Start Date:', startDateFormatted);
    console.log('Formatted End Date:', endDateFormatted);

    if (location || minGuests !== undefined || startDay || endDay) {
      this.accommodationService.searchAccommodations(location, minGuests, startDateFormatted, endDateFormatted).subscribe(
        (data: Accommodation[]) => {
          this.accommodations = data;
        },
        (error) => {
          console.error(error);
          if (error.status === 503 ) {
            this.openSnackBar("We have no search results for these dates, please try again with a different entry or without an interval.", "");
          }
          else if (error.status === 502 ) {
            this.openSnackBar("We have no search results for these dates, please try again with a different entry or without an interval.", "");
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
